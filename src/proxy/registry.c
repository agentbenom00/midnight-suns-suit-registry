// Parse / extend a UE 4.26 cooked AssetRegistry.bin (FAssetRegistryVersion 8 = FixedTags), as used by Midnight Suns.
//
// Layout: FAssetRegistryVersion (guid16 + int32) | name batch | tag store | assets array | dependency section | packages
//   name batch: int32 Num, uint32 NumStringBytes, uint64 HashVersion, uint64 Hashes[Num], uint16be headers[Num]
//               (bit 15 = utf16, low 10 bits = length), then the strings back to back
//   FName: uint32 index (bit 31 set -> a uint32 number follows)
//   tag store: uint32 begin magic, int32 nums[11]; magic 0x12345679 = "text first": uint32 text-block size +
//              Texts FString[n4] come first; then NumberlessNames u32[n0], Names FName[n1],
//              NumberlessExportPaths (3 x u32)[n2], ExportPaths (3 x FName)[n3], (Texts here in the old order),
//              AnsiStringOffsets u32[n5], WideStringOffsets u32[n6], AnsiStrings u8[n7], WideStrings u16[n8],
//              NumberlessPairs (u32 key name, u32 value id)[n9], Pairs (FName key, u32 value id)[n10], end magic
//   value id: type in the low 3 bits (0 ansi, 1 wide, 2 numberless name, 3 name, 4/5 export paths, 6 text)
//   map handle (uint64): bit 63 = numberless keys, bits 32-47 = Num, low 32 = PairBegin
//   asset: ObjectPath, PackagePath, AssetClass, PackageName, AssetName (FNames), uint64 tag map handle,
//          bundles (int32 n + entries), ChunkIDs (int32 n + int32[n]), uint32 PackageFlags
// Cloned entries are appended at the END of each array, so all existing indices stay valid; only counts change.
#include "sr.h"

typedef struct { uint64_t h; uint32_t first, last; } nslot;     // first == UINT32_MAX: empty
typedef struct { uint32_t key; uint32_t start, end; } aslot;

struct reg {
    uint8_t *b;
    size_t n;
    size_t nb_start, hash_at, hdr_at, str_at, nb_end;
    uint32_t nnames;
    uint64_t hash_version;
    uint32_t *name_off;                                         // byte offset of each name's characters
    size_t store_start, nums_at, nlnames_at, nlpairs_at, nlpairs_end, store_end;
    int32_t nums[11];
    size_t assets_at, assets_end;
    int32_t nassets;
    nslot *names; uint64_t nmask;
    aslot *assets; uint64_t amask;
    // patch state
    char **new_names; uint32_t n_new, cap_new;
    uint32_t *new_nl; uint32_t n_nl, cap_nl;
    uint32_t *new_pairs; uint32_t n_pairs, cap_pairs;          // key, value
    buf new_assets;
    uint32_t n_new_assets;
};

static inline int name_wide(reg *r, uint32_t i) { return (r->b[r->hdr_at + 2 * i] & 0x80) != 0; }
static inline uint32_t name_len(reg *r, uint32_t i)
{
    return (((uint32_t)r->b[r->hdr_at + 2 * i] << 8) | r->b[r->hdr_at + 2 * i + 1]) & 0x3ff;
}

// narrow name i, or a new name, as bytes
static const char *name_bytes(reg *r, uint32_t i, uint32_t *len)
{
    if (i >= r->nnames) {
        const char *s = r->new_names[i - r->nnames];
        *len = (uint32_t)strlen(s);
        return s;
    }
    *len = name_len(r, i);
    return (const char *)r->b + r->name_off[i];
}

static uint64_t key_hash(const char *s, size_t n, int wide) { return fnv1a64(s, n) ^ (wide ? 0x9e3779b97f4a7c15ull : 0); }

static nslot *name_slot(reg *r, const char *s, size_t n, int wide, uint64_t h)
{
    for (uint64_t k = h & r->nmask;; k = (k + 1) & r->nmask) {
        nslot *sl = &r->names[k];
        if (sl->first == UINT32_MAX) return sl;
        if (sl->h != h) continue;
        uint32_t i = sl->first, len;
        int w = i < r->nnames && name_wide(r, i);
        if (w != wide) continue;
        const char *t = name_bytes(r, i, &len);
        if (w) len *= 2;
        if (len == n && !memcmp(t, s, n)) return sl;
    }
}

static aslot *asset_slot(reg *r, uint32_t key)
{
    for (uint64_t k = (key * 0x9e3779b97f4a7c15ull) >> 20 & r->amask;; k = (k + 1) & r->amask) {
        aslot *sl = &r->assets[k];
        if (sl->key == UINT32_MAX || sl->key == key) return sl;
    }
}

static void fname(rd *rr, uint32_t *i, uint32_t *num)
{
    uint32_t v = rd_u32(rr);
    *num = 0;
    if (v & 0x80000000u) { v &= 0x7fffffff; *num = rd_u32(rr); }
    *i = v;
}

reg *reg_parse(uint8_t *data, size_t n)
{
    reg *r = xcalloc(1, sizeof *r);
    r->b = data;
    r->n = n;
    rd rr = {data, n, 16};
    if (rd_i32(&rr) != 8) sr_fail("unsupported AssetRegistry version (expected 8)");
    r->nb_start = rr.at;
    int32_t nn = rd_i32(&rr);
    uint32_t nbytes = rd_u32(&rr);
    r->hash_version = rd_u64(&rr);
    if (nn < 0) sr_fail("bad name count");
    r->nnames = (uint32_t)nn;
    r->hash_at = rr.at; rd_skip(&rr, 8ull * nn);
    r->hdr_at = rr.at; rd_skip(&rr, 2ull * nn);
    r->str_at = rr.at;
    r->name_off = xmalloc(sizeof(uint32_t) * (nn + 1));
    uint64_t cap = 1;
    while (cap < 2ull * nn + 4096) cap <<= 1;
    r->names = xmalloc(sizeof(nslot) * cap);
    memset(r->names, 0xff, sizeof(nslot) * cap);
    r->nmask = cap - 1;
    size_t q = r->str_at;
    for (uint32_t i = 0; i < r->nnames; i++) {
        uint32_t len = name_len(r, i), bytes = name_wide(r, i) ? 2 * len : len;
        if (q + bytes > n) sr_fail("truncated name batch");
        r->name_off[i] = (uint32_t)q;
        uint64_t h = key_hash((const char *)data + q, bytes, name_wide(r, i));
        nslot *sl = name_slot(r, (const char *)data + q, bytes, name_wide(r, i), h);
        if (sl->first == UINT32_MAX) { sl->h = h; sl->first = sl->last = i; }
        else sl->last = i;
        q += bytes;
    }
    if (q - r->str_at != nbytes) sr_fail("name batch size mismatch");
    rr.at = r->nb_end = q;
    // tag store
    r->store_start = rr.at;
    uint32_t magic = rd_u32(&rr);
    if (magic != 0x12345678 && magic != 0x12345679) sr_fail("bad tag store magic");
    int text_first = magic == 0x12345679;
    r->nums_at = rr.at;
    for (int i = 0; i < 11; i++) { r->nums[i] = rd_i32(&rr); if (r->nums[i] < 0) sr_fail("bad tag store count"); }
    if (text_first) {
        rd_u32(&rr);
        for (int i = 0; i < r->nums[4]; i++) rd_skip_fstring(&rr);
    }
    uint32_t a, b2;
    r->nlnames_at = rr.at; rd_skip(&rr, 4ull * r->nums[0]);
    for (int i = 0; i < r->nums[1]; i++) fname(&rr, &a, &b2);
    rd_skip(&rr, 12ull * r->nums[2]);
    for (int i = 0; i < r->nums[3]; i++) { fname(&rr, &a, &b2); fname(&rr, &a, &b2); fname(&rr, &a, &b2); }
    if (!text_first)
        for (int i = 0; i < r->nums[4]; i++) rd_skip_fstring(&rr);
    rd_skip(&rr, 4ull * r->nums[5] + 4ull * r->nums[6] + (uint64_t)r->nums[7] + 2ull * r->nums[8]);
    r->nlpairs_at = rr.at; rd_skip(&rr, 8ull * r->nums[9]);
    r->nlpairs_end = rr.at;
    for (int i = 0; i < r->nums[10]; i++) { fname(&rr, &a, &b2); rd_u32(&rr); }
    if (rd_u32(&rr) != 0x87654321) sr_fail("bad tag store end magic");
    r->store_end = rr.at;
    // assets
    r->assets_at = rr.at;
    r->nassets = rd_i32(&rr);
    if (r->nassets < 0) sr_fail("bad asset count");
    cap = 1;
    while (cap < 2ull * r->nassets + 64) cap <<= 1;
    r->assets = xmalloc(sizeof(aslot) * cap);
    memset(r->assets, 0xff, sizeof(aslot) * cap);
    r->amask = cap - 1;
    for (int32_t k = 0; k < r->nassets; k++) {
        size_t s = rr.at;
        uint32_t oi, on;
        fname(&rr, &oi, &on);
        for (int f = 0; f < 4; f++) fname(&rr, &a, &b2);
        rd_u64(&rr);
        int32_t nb = rd_i32(&rr);
        for (int32_t i = 0; i < nb; i++) {
            fname(&rr, &a, &b2);
            int32_t m = rd_i32(&rr);
            for (int32_t j = 0; j < m; j++) { fname(&rr, &a, &b2); rd_skip_fstring(&rr); }
        }
        int32_t nc = rd_i32(&rr);
        if (nc < 0) sr_fail("bad chunk count");
        rd_skip(&rr, 4ull * nc);
        rd_u32(&rr);
        if (on == 0) {                                          // (index, 0) -> record; the last one wins
            aslot *sl = asset_slot(r, oi);
            sl->key = oi;
            sl->start = (uint32_t)s;
            sl->end = (uint32_t)rr.at;
        }
    }
    r->assets_end = rr.at;
    return r;
}

void reg_free(reg *r)
{
    if (!r) return;
    free(r->b);
    free(r->name_off);
    free(r->names);
    free(r->assets);
    for (uint32_t i = 0; i < r->n_new; i++) free(r->new_names[i]);
    free(r->new_names);
    free(r->new_nl);
    free(r->new_pairs);
    buf_free(&r->new_assets);
    free(r);
}

// index of a name string: an existing (narrow) name -> its last occurrence; otherwise a new name is appended
static uint32_t name_index(reg *r, const char *s)
{
    size_t n = strlen(s);
    uint64_t h = key_hash(s, n, 0);
    nslot *sl = name_slot(r, s, n, 0, h);
    if (sl->first != UINT32_MAX) return sl->last;
    if (r->n_new == r->cap_new) {
        r->cap_new = r->cap_new ? 2 * r->cap_new : 256;
        r->new_names = xrealloc(r->new_names, sizeof(char *) * r->cap_new);
    }
    for (const char *c = s; *c; c++)
        if ((uint8_t)*c > 0x7f) sr_fail("new names must be ASCII: %s", s);
    if (n >= 1024) sr_fail("name too long: %.80s...", s);
    r->new_names[r->n_new] = xstrdup(s);
    uint32_t idx = r->nnames + r->n_new++;
    if ((uint64_t)(r->nnames + r->n_new) * 2 > r->nmask) sr_fail("too many new names");
    sl->h = h; sl->first = sl->last = idx;
    return idx;
}

// the name as a C string (NULL for UTF-16 names: those are never renamed)
static char *name_str(reg *r, uint32_t i)
{
    if (i >= r->nnames + r->n_new) sr_fail("bad name index %u", i);
    if (i < r->nnames && name_wide(r, i)) return NULL;
    uint32_t len;
    const char *t = name_bytes(r, i, &len);
    char *s = xmalloc(len + 1);
    memcpy(s, t, len);
    s[len] = 0;
    return s;
}

static void put_fname(buf *o, uint32_t i, uint32_t num)
{
    if (num == 0) buf_u32(o, i);
    else { buf_u32(o, i | 0x80000000u); buf_u32(o, num); }
}

// FName at rr: write it renamed (new index if the text changes)
static void clone_fname(reg *r, rd *rr, buf *o, rename_fn rn, void *ctx)
{
    uint32_t i, num;
    fname(rr, &i, &num);
    char *s = name_str(r, i);
    char *t = s ? rn(s, ctx) : NULL;
    put_fname(o, t ? name_index(r, t) : i, num);
    free(s);
    free(t);
}

int reg_clone(reg *r, const char *object_path, rename_fn rn, void *ctx)
{
    size_t n = strlen(object_path);
    nslot *ns = name_slot(r, object_path, n, 0, key_hash(object_path, n, 0));
    if (ns->first == UINT32_MAX || ns->first >= r->nnames) return -1;
    aslot *as = asset_slot(r, ns->first);
    if (as->key == UINT32_MAX) return -1;
    rd rr = {r->b, as->end, as->start};
    buf o = {0};
    for (int k = 0; k < 5; k++) clone_fname(r, &rr, &o, rn, ctx);
    uint64_t h = rd_u64(&rr);
    uint32_t num = (uint32_t)((h >> 32) & 0xffff), begin = (uint32_t)h;
    if (!(h >> 63)) sr_fail("%s: only numberless-key tag maps are handled", object_path);
    if ((uint64_t)begin + num > (uint64_t)r->nums[9]) sr_fail("%s: bad tag map", object_path);
    uint32_t new_begin = (uint32_t)r->nums[9] + r->n_pairs;
    for (uint32_t k = 0; k < num; k++) {
        const uint8_t *pp = r->b + r->nlpairs_at + 8ull * (begin + k);
        uint32_t key = rd32(pp), vid = rd32(pp + 4), t = vid & 7, idx = vid >> 3;
        if (t == 2) {                                           // numberless name value
            if (idx >= (uint32_t)r->nums[0]) sr_fail("%s: bad name value", object_path);
            char *s = name_str(r, rd32(r->b + r->nlnames_at + 4ull * idx));
            char *nw = s ? rn(s, ctx) : NULL;
            if (nw) {
                vid = (((uint32_t)r->nums[0] + r->n_nl) << 3) | 2;
                if (r->n_nl == r->cap_nl) { r->cap_nl = r->cap_nl ? 2 * r->cap_nl : 256; r->new_nl = xrealloc(r->new_nl, 4 * r->cap_nl); }
                r->new_nl[r->n_nl++] = name_index(r, nw);
            }
            free(s);
            free(nw);
        } else if (t != 0 && t != 1 && t != 6) {                // strings/texts are reused as they are
            sr_fail("%s: tag value type %u is not handled", object_path, t);
        }
        if (r->n_pairs + 1 >= r->cap_pairs) { r->cap_pairs = r->cap_pairs ? 2 * r->cap_pairs : 512; r->new_pairs = xrealloc(r->new_pairs, 8ull * r->cap_pairs); }
        r->new_pairs[2 * r->n_pairs] = key;
        r->new_pairs[2 * r->n_pairs + 1] = vid;
        r->n_pairs++;
    }
    buf_u64(&o, (1ull << 63) | ((uint64_t)num << 32) | new_begin);
    int32_t nb = rd_i32(&rr);
    buf_u32(&o, (uint32_t)nb);
    for (int32_t k = 0; k < nb; k++) {
        clone_fname(r, &rr, &o, rn, ctx);
        int32_t m = rd_i32(&rr);
        buf_u32(&o, (uint32_t)m);
        for (int32_t j = 0; j < m; j++) {
            clone_fname(r, &rr, &o, rn, ctx);
            size_t p0 = rr.at;
            rd_skip_fstring(&rr);
            buf_put(&o, r->b + p0, rr.at - p0);
        }
    }
    buf_put(&o, r->b + rr.at, as->end - rr.at);                 // chunk IDs + package flags
    buf_put(&r->new_assets, o.p, o.n);
    r->n_new_assets++;
    buf_free(&o);
    return 0;
}

uint8_t *reg_build(reg *r, size_t *outn)
{
    const uint8_t *b = r->b;
    size_t new_str = 0;
    for (uint32_t i = 0; i < r->n_new; i++) new_str += strlen(r->new_names[i]);
    buf o = {0};
    buf_reserve(&o, r->n + r->n_new * 10ull + new_str + r->n_nl * 4ull + r->n_pairs * 8ull + r->new_assets.n + 64);
#define COPY(a, z) buf_put(&o, b + (a), (z) - (a))
    COPY(0, r->nb_start);
    uint32_t nbytes = rd32(b + r->nb_start + 4);
    buf_u32(&o, r->nnames + r->n_new);
    buf_u32(&o, nbytes + (uint32_t)new_str);
    buf_u64(&o, r->hash_version);
    COPY(r->hash_at, r->hdr_at);
    for (uint32_t i = 0; i < r->n_new; i++) {
        // UE name hash: CityHash64 of the lowercase name
        size_t n = strlen(r->new_names[i]);
        char *lw = xstrdup(r->new_names[i]);
        for (size_t k = 0; k < n; k++) if (lw[k] >= 'A' && lw[k] <= 'Z') lw[k] += 32;
        buf_u64(&o, city_hash64((const uint8_t *)lw, n));
        free(lw);
    }
    COPY(r->hdr_at, r->str_at);
    for (uint32_t i = 0; i < r->n_new; i++) buf_u16be(&o, (uint16_t)strlen(r->new_names[i]));
    COPY(r->str_at, r->nb_end);
    for (uint32_t i = 0; i < r->n_new; i++) buf_put(&o, r->new_names[i], strlen(r->new_names[i]));
    // tag store
    COPY(r->store_start, r->nums_at);
    for (int i = 0; i < 11; i++)
        buf_u32(&o, (uint32_t)(r->nums[i] + (i == 0 ? (int32_t)r->n_nl : i == 9 ? (int32_t)r->n_pairs : 0)));
    size_t nl_end = r->nlnames_at + 4ull * r->nums[0];
    COPY(r->nums_at + 44, nl_end);
    buf_put(&o, r->new_nl, 4ull * r->n_nl);
    COPY(nl_end, r->nlpairs_end);
    buf_put(&o, r->new_pairs, 8ull * r->n_pairs);
    COPY(r->nlpairs_end, r->store_end);
    // assets
    buf_u32(&o, (uint32_t)(r->nassets + (int32_t)r->n_new_assets));
    COPY(r->assets_at + 4, r->assets_end);
    buf_put(&o, r->new_assets.p, r->new_assets.n);
    COPY(r->assets_end, r->n);
#undef COPY
    *outn = o.n;
    return o.p;
}
