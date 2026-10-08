// UE4 pak reading (versions 3-11: legacy index, or the v10+ encoded entries + full directory index) and writing
// (version 11, Zlib 64 KiB blocks, encoded entries + path hash index + full directory index, like UnrealPak/repak).
#include "sr.h"

#define PAK_MAGIC 0x5A6F12E1u
static const uint8_t AES_KEY[32] = {0xDE, 0x52, 0x8B, 0x9B, 0x92, 0xCF, 0x69, 0x0B, 0xC9, 0x28, 0x16, 0xC9, 0x98, 0xFB, 0x79, 0x08,
                                    0xB0, 0x53, 0xD1, 0x86, 0xE2, 0xD0, 0x8B, 0xFF, 0x6D, 0x61, 0x37, 0x0D, 0xC5, 0xBF, 0x35, 0xAF};

static void read_at(HANDLE h, int64_t off, void *p, size_t n)
{
    LARGE_INTEGER li;
    li.QuadPart = off;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) sr_fail("seek failed");
    uint8_t *q = p;
    while (n) {
        DWORD k = n > (1u << 30) ? (1u << 30) : (DWORD)n, got = 0;
        if (!ReadFile(h, q, k, &got, NULL) || got == 0) sr_fail("read failed");
        q += got; n -= got;
    }
}

static uint8_t *read_maybe_encrypted(pak *pk, int64_t off, int64_t n, int encrypted)
{
    if (n < 0 || n > (1ll << 31)) sr_fail("bad pak data size");
    size_t m = encrypted ? (size_t)((n + 15) & ~15ll) : (size_t)n;
    if (off < 0 || off + (int64_t)m > pk->length) sr_fail("pak data out of range");
    uint8_t *p = xmalloc(m + 1);
    read_at(pk->h, off, p, m);
    if (encrypted) aes256_ecb_decrypt(AES_KEY, p, m);
    return p;
}

static int allow_aes_flag;

int pak_open(pak *pk, const wchar_t *path, int allow_aes)
{
    memset(pk, 0, sizeof *pk);
    pk->h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (pk->h == INVALID_HANDLE_VALUE) { pk->h = NULL; return -1; }
    LARGE_INTEGER sz;
    GetFileSizeEx(pk->h, &sz);
    pk->length = sz.QuadPart;
    // footer: 221 (v8+, 5 method names), 189 (4 names), 61 (v7, + key guid), 45 (v4-6, + encrypted flag), 44 (v1-3)
    static const struct { int size, magic_at, min_v, max_v, names; } F[] = {
        {221, 17, 8, 11, 5}, {189, 17, 8, 11, 4}, {61, 17, 7, 7, 0}, {45, 1, 4, 6, 0}, {44, 0, 1, 3, 0}};
    uint8_t foot[221];
    int found = -1;
    for (int i = 0; i < 5 && found < 0; i++) {
        if (pk->length < F[i].size) continue;
        read_at(pk->h, pk->length - F[i].size, foot, F[i].size);
        int v = (int)rd32(foot + F[i].magic_at + 4);
        if (rd32(foot + F[i].magic_at) == PAK_MAGIC && v >= F[i].min_v && v <= F[i].max_v) found = i;
    }
    if (found < 0) { pak_close(pk); return -1; }
    const uint8_t *m = foot + F[found].magic_at;
    pk->version = (int)rd32(m + 4);
    pk->encrypted_index = F[found].magic_at > 0 ? foot[F[found].magic_at - 1] : 0;
    int64_t index_off = (int64_t)rd64(m + 8), index_size = (int64_t)rd64(m + 16);
    strcpy(pk->methods[0], "None");
    if (F[found].names) {
        for (int i = 0; i < F[found].names; i++) {
            memcpy(pk->methods[i + 1], m + 44 + 32 * i, 32);
            pk->methods[i + 1][32] = 0;
        }
    } else {                                                // pre-v8: compression flags 1 zlib, 2 gzip, 4 custom (Oodle)
        strcpy(pk->methods[1], "Zlib"); strcpy(pk->methods[2], "Gzip"); strcpy(pk->methods[3], "Oodle");
    }
    if (pk->encrypted_index && !allow_aes) { pak_close(pk); return -2; }
    allow_aes_flag = allow_aes;
    pk->index = read_maybe_encrypted(pk, index_off, index_size, pk->encrypted_index);
    pk->index_n = (size_t)index_size;

    rd r = {pk->index, pk->index_n, 0};
    char *mount = rd_fstring(&r);
    for (char *c = mount; *c; c++) if (*c == '\\') *c = '/';
    const char *mp = mount;
    while (!strncmp(mp, "../", 3)) mp += 3;                 // "../../../" = the game folder
    if (*mp == '/') mp++;
    pk->mount = xstrdup(mp);
    size_t ml = strlen(pk->mount);
    if (ml && pk->mount[ml - 1] != '/') { pk->mount = xrealloc(pk->mount, ml + 2); strcpy(pk->mount + ml, "/"); }
    free(mount);
    if (pk->version >= 10) {
        rd_i32(&r);                                         // entry count
        rd_u64(&r);                                         // path hash seed
        if (rd_u32(&r)) rd_skip(&r, 8 + 8 + 20);            // path hash index (not needed)
        if (!rd_u32(&r)) sr_fail("pak has no directory index");
        pk->fdi_offset = (int64_t)rd_u64(&r);
        pk->fdi_size = (int64_t)rd_u64(&r);
        rd_skip(&r, 20);
        uint32_t n = rd_u32(&r);
        rd_need(&r, n);
        pk->encoded = (uint8_t *)r.p + r.at;
        pk->encoded_n = n;
        rd_skip(&r, n);
        pk->legacy_count = rd_i32(&r);                      // entries that could not be encoded
        pk->legacy = (uint8_t *)r.p + r.at;
        pk->legacy_n = r.n - r.at;
    } else {
        pk->legacy_count = rd_i32(&r);
        pk->legacy = (uint8_t *)r.p + r.at;
        pk->legacy_n = r.n - r.at;
    }
    return 0;
}

void pak_close(pak *pk)
{
    if (pk->h) CloseHandle(pk->h);
    free(pk->index);
    free(pk->mount);
    memset(pk, 0, sizeof *pk);
}

static int header_size(int version, int method, int nblocks)
{
    int n = 8 + 8 + 8 + 4 + 20;
    if (version <= 1) n += 8;
    if (version >= 3) n += (method ? 4 + 16 * nblocks : 0) + 1 + 4;
    return n;
}

// serialized FPakEntry (legacy index entries and the non-encoded list of v10+)
static void decode_legacy(pak *pk, rd *r, pak_entry *e)
{
    e->offset = (int64_t)rd_u64(r);
    e->size = (int64_t)rd_u64(r);
    e->usize = (int64_t)rd_u64(r);
    uint32_t m = rd_u32(r);
    if (pk->version < 8) m = (m & 1) ? 1 : (m & 2) ? 2 : (m & 4) ? 3 : 0;
    if (m > 5) sr_fail("bad compression method %u", m);
    e->method = (int)m;
    if (pk->version <= 1) rd_u64(r);
    rd_skip(r, 20);
    int64_t base = pk->version >= 5 ? e->offset : 0;
    if (pk->version >= 3) {
        if (e->method) {
            e->nblocks = (int)rd_u32(r);
            if (e->nblocks < 0 || e->nblocks > (1 << 24)) sr_fail("bad block count");
            e->blocks = xmalloc(sizeof(int64_t) * 2 * (e->nblocks + 1));
            for (int i = 0; i < e->nblocks; i++) {
                e->blocks[2 * i] = base + (int64_t)rd_u64(r);
                e->blocks[2 * i + 1] = base + (int64_t)rd_u64(r);
            }
        }
        e->encrypted = rd_u8(r) & 1;
        e->block_size = rd_u32(r);
    }
    if (!e->method) {
        e->nblocks = 1;
        free(e->blocks);
        e->blocks = xmalloc(sizeof(int64_t) * 2);
        e->blocks[0] = e->offset + header_size(pk->version, 0, 0);
        e->blocks[1] = e->blocks[0] + e->size;
    }
}

static void decode_encoded(pak *pk, int32_t at, pak_entry *e)
{
    if (at < 0) {                                            // in the non-encoded list
        int idx = -at - 1;
        if (idx >= pk->legacy_count) sr_fail("bad pak entry location");
        rd r = {pk->legacy, pk->legacy_n, 0};
        pak_entry tmp = {0};
        for (int i = 0; i <= idx; i++) {
            free(tmp.blocks); memset(&tmp, 0, sizeof tmp);
            decode_legacy(pk, &r, &tmp);
        }
        tmp.path = e->path;
        *e = tmp;
        return;
    }
    rd r = {pk->encoded, pk->encoded_n, (size_t)at};
    uint32_t flags = rd_u32(&r);
    e->block_size = (flags & 0x3f) == 0x3f ? rd_u32(&r) : (flags & 0x3f) << 11;
    e->offset = (flags & (1u << 31)) ? rd_u32(&r) : (int64_t)rd_u64(&r);
    e->usize = (flags & (1u << 30)) ? rd_u32(&r) : (int64_t)rd_u64(&r);
    e->method = (int)((flags >> 23) & 0x3f);
    if (e->method > 5) sr_fail("bad compression method");
    e->size = e->usize;
    if (e->method) e->size = (flags & (1u << 29)) ? rd_u32(&r) : (int64_t)rd_u64(&r);
    e->encrypted = (flags >> 22) & 1;
    int nb = (int)((flags >> 6) & 0xffff);
    int hdr = header_size(pk->version, e->method, nb);
    if (!e->method) {
        e->nblocks = 1;
        e->blocks = xmalloc(sizeof(int64_t) * 2);
        e->blocks[0] = e->offset + hdr;
        e->blocks[1] = e->blocks[0] + e->size;
        return;
    }
    e->nblocks = nb;
    e->blocks = xmalloc(sizeof(int64_t) * 2 * (nb + 1));
    if (nb == 1 && !e->encrypted) {
        e->blocks[0] = e->offset + hdr;
        e->blocks[1] = e->blocks[0] + e->size;
        return;
    }
    int64_t p = e->offset + hdr;
    for (int i = 0; i < nb; i++) {
        uint32_t bs = rd_u32(&r);
        e->blocks[2 * i] = p;
        e->blocks[2 * i + 1] = p + bs;
        p += e->encrypted ? ((bs + 15) & ~15u) : bs;
    }
}

static char *join_path(const char *a, const char *b, const char *c)
{
    size_t na = strlen(a), nb = strlen(b), nc = strlen(c);
    char *s = xmalloc(na + nb + nc + 1);
    memcpy(s, a, na); memcpy(s + na, b, nb); memcpy(s + na + nb, c, nc + 1);
    return s;
}

pak_entry *pak_list(pak *pk, pak_filter f, void *ctx, int *count)
{
    pak_entry *out = NULL;
    int n = 0, cap = 0;
#define ADD(dir_, name_) do { \
        if (n == cap) { cap = cap ? 2 * cap : 16; out = xrealloc(out, cap * sizeof *out); } \
        memset(&out[n], 0, sizeof out[n]); \
        out[n].path = join_path(dir_, name_, ""); \
    } while (0)
    if (pk->version >= 10) {
        uint8_t *fdi = read_maybe_encrypted(pk, pk->fdi_offset, pk->fdi_size, pk->encrypted_index);
        rd r = {fdi, (size_t)pk->fdi_size, 0};
        int32_t dirs = rd_i32(&r);
        for (int d = 0; d < dirs; d++) {
            char *dn = rd_fstring(&r);
            const char *rel = !strcmp(dn, "/") ? "" : dn[0] == '/' ? dn + 1 : dn;
            char *dir = join_path(pk->mount, rel, "");
            int32_t files = rd_i32(&r);
            // most directories are of no interest: ask once with an empty name
            int want_dir = f(dir, NULL, ctx);
            for (int i = 0; i < files; i++) {
                if (!want_dir) { rd_skip_fstring(&r); rd_i32(&r); continue; }
                char *name = rd_fstring(&r);
                int32_t loc = rd_i32(&r);
                if (f(dir, name, ctx)) {
                    ADD(dir, name);
                    decode_encoded(pk, loc, &out[n]);
                    n++;
                }
                free(name);
            }
            free(dir);
            free(dn);
        }
        free(fdi);
    } else {
        rd r = {pk->legacy, pk->legacy_n, 0};
        for (int i = 0; i < pk->legacy_count; i++) {
            char *name = rd_fstring(&r);
            for (char *c = name; *c; c++) if (*c == '\\') *c = '/';
            pak_entry tmp = {0};
            decode_legacy(pk, &r, &tmp);
            char *slash = strrchr(name, '/');
            char *dir, *file;
            if (slash) { *slash = 0; dir = join_path(pk->mount, name, "/"); file = slash + 1; }
            else { dir = xstrdup(pk->mount); file = name; }
            if (f(dir, NULL, ctx) && f(dir, file, ctx)) {
                ADD(dir, file);
                tmp.path = out[n].path;
                out[n] = tmp;
                n++;
            } else free(tmp.blocks);
            free(dir);
            free(name);
        }
    }
#undef ADD
    *count = n;
    return out;
}

void pak_entries_free(pak_entry *e, int count)
{
    for (int i = 0; i < count; i++) { free(e[i].path); free(e[i].blocks); }
    free(e);
}

uint8_t *pak_read(pak *pk, pak_entry *e, int allow_oodle)
{
    if (e->usize < 0 || e->usize > 0x7fff0000) sr_fail("%s: too large", e->path);
    if (e->encrypted && !allow_aes_flag) sr_fail("%s is encrypted", e->path);
    const char *name = pk->methods[e->method];
    uint8_t *out = xmalloc((size_t)e->usize + 1);
    if (!e->method) {
        uint8_t *p = read_maybe_encrypted(pk, e->blocks[0], e->size, e->encrypted);
        memcpy(out, p, (size_t)e->usize);
        free(p);
        return out;
    }
    int oodle = !strcmp(name, "Oodle");
    if (!oodle && strcmp(name, "Zlib")) sr_fail("%s: compression %s is not supported", e->path, name);
    if (oodle && (!allow_oodle || !oodle_load(0))) sr_fail("%s needs Oodle", e->path);
    uint32_t bs = e->block_size ? e->block_size : (uint32_t)e->usize;
    for (int i = 0; i < e->nblocks; i++) {
        int64_t s = e->blocks[2 * i], end = e->blocks[2 * i + 1];
        uint8_t *c = read_maybe_encrypted(pk, s, end - s, e->encrypted);
        int64_t uoff = (int64_t)i * bs;
        if (uoff >= e->usize) sr_fail("%s: bad compression blocks", e->path);
        size_t ulen = (size_t)((e->usize - uoff) < bs ? (e->usize - uoff) : bs);
        int bad = oodle ? oodle_decompress(c, (size_t)(end - s), out + uoff, ulen)
                        : inflate_zlib(c, (size_t)(end - s), out + uoff, ulen);
        free(c);
        if (bad) sr_fail("%s: block %d could not be decompressed", e->path, i);
    }
    return out;
}

// ================================================================ writer

#define BLOCK 0x10000

typedef struct { char *path; int64_t offset, size, usize; int method; int nblocks; uint32_t *bsizes; } wentry;

struct pak_writer {
    HANDLE h;
    int64_t pos;
    wentry *e;
    int n, cap;
};

static void wr(pak_writer *w, const void *p, size_t n)
{
    const uint8_t *q = p;
    while (n) {
        DWORD k = n > (1u << 30) ? (1u << 30) : (DWORD)n, put = 0;
        if (!WriteFile(w->h, q, k, &put, NULL) || put != k) sr_fail("could not write the registry pak (disk full?)");
        q += k; n -= k; w->pos += k;
    }
}

pak_writer *pak_write_begin(const wchar_t *tmp_path)
{
    HANDLE h = CreateFileW(tmp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    pak_writer *w = xcalloc(1, sizeof *w);
    w->h = h;
    return w;
}

typedef struct {
    const uint8_t *data;
    size_t n;
    int nblocks;
    uint8_t **out;
    size_t *outn;
    volatile LONG next;
    volatile LONG failed;
} job;

static DWORD WINAPI compress_worker(LPVOID arg)
{
    job *j = arg;
    for (;;) {
        LONG i = InterlockedIncrement(&j->next) - 1;
        if (i >= j->nblocks) return 0;
        size_t off = (size_t)i * BLOCK, len = j->n - off < BLOCK ? j->n - off : BLOCK;
        size_t cap = deflate_bound(len);
        uint8_t *o = malloc(cap);
        size_t got = o ? deflate_zlib(j->data + off, len, o, cap) : 0;
        if (!got) { free(o); InterlockedExchange(&j->failed, 1); return 0; }
        j->out[i] = o;
        j->outn[i] = got;
    }
}

static void write_header(pak_writer *w, wentry *e, const uint8_t sha[20])
{
    buf b = {0};
    buf_u64(&b, 0);                                          // offset (0 in the inline header)
    buf_u64(&b, (uint64_t)e->size);
    buf_u64(&b, (uint64_t)e->usize);
    buf_u32(&b, (uint32_t)e->method);
    buf_put(&b, sha, 20);
    if (e->method) {
        buf_u32(&b, (uint32_t)e->nblocks);
        uint64_t at = (uint64_t)header_size(11, e->method, e->nblocks);
        for (int i = 0; i < e->nblocks; i++) { buf_u64(&b, at); buf_u64(&b, at + e->bsizes[i]); at += e->bsizes[i]; }
    }
    buf_u8(&b, 0);
    buf_u32(&b, e->method ? BLOCK : 0);
    wr(w, b.p, b.n);
    buf_free(&b);
}

void pak_write_file(pak_writer *w, const char *path, const uint8_t *data, size_t n, int compress)
{
    if (w->n == w->cap) { w->cap = w->cap ? 2 * w->cap : 16; w->e = xrealloc(w->e, w->cap * sizeof *w->e); }
    wentry *e = &w->e[w->n++];
    memset(e, 0, sizeof *e);
    e->path = xstrdup(path);
    e->offset = w->pos;
    e->usize = (int64_t)n;
    uint8_t sha[20];
    if (!compress) {
        e->size = (int64_t)n;
        sha1(data, n, sha);
        write_header(w, e, sha);
        wr(w, data, n);
        return;
    }
    job j = {data, n, (int)((n + BLOCK - 1) / BLOCK), NULL, NULL, 0, 0};
    if (j.nblocks > 0xffff) sr_fail("%s is too large for one pak entry", path);
    j.out = xcalloc(j.nblocks, sizeof *j.out);
    j.outn = xcalloc(j.nblocks, sizeof *j.outn);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int nt = (int)si.dwNumberOfProcessors;
    if (nt < 1) nt = 1;
    if (nt > 32) nt = 32;
    HANDLE th[32];
    int started = 0;
    for (int i = 0; i < nt; i++) {
        th[started] = CreateThread(NULL, 0, compress_worker, &j, 0, NULL);
        if (th[started]) started++;
    }
    if (!started) compress_worker(&j);
    else WaitForMultipleObjects(started, th, TRUE, INFINITE);
    for (int i = 0; i < started; i++) CloseHandle(th[i]);
    if (j.failed) sr_fail("compression failed (out of memory?)");
    e->method = 1;
    e->nblocks = j.nblocks;
    e->bsizes = xmalloc(sizeof(uint32_t) * (j.nblocks + 1));
    sha1_ctx *c = sha1_begin();
    for (int i = 0; i < j.nblocks; i++) {
        e->bsizes[i] = (uint32_t)j.outn[i];
        e->size += (int64_t)j.outn[i];
        sha1_add(c, j.out[i], j.outn[i]);
    }
    sha1_end(c, sha);
    write_header(w, e, sha);
    for (int i = 0; i < j.nblocks; i++) { wr(w, j.out[i], j.outn[i]); free(j.out[i]); }
    free(j.out);
    free(j.outn);
}

static uint64_t fnv64_path(const char *path, uint64_t seed)
{
    uint64_t h = 0xcbf29ce484222325ull + seed;
    for (const char *c = path; *c; c++) {
        uint8_t ch = (uint8_t)*c;
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        h ^= ch; h *= 0x100000001b3ull;                      // UTF-16LE: the character, then a 0 byte
        h ^= 0; h *= 0x100000001b3ull;
    }
    return h;
}

void pak_write_end(pak_writer *w)
{
    buf enc = {0};
    int32_t *loc = xmalloc(sizeof(int32_t) * (w->n + 1));
    for (int i = 0; i < w->n; i++) {
        wentry *e = &w->e[i];
        loc[i] = (int32_t)enc.n;
        int off32 = e->offset <= 0xffffffffll, us32 = e->usize <= 0xffffffffll, s32 = e->size <= 0xffffffffll;
        uint32_t flags = (off32 ? 1u << 31 : 0) | (us32 ? 1u << 30 : 0) | (s32 ? 1u << 29 : 0) |
                         ((uint32_t)e->method << 23) | ((uint32_t)e->nblocks << 6) | (e->method ? BLOCK >> 11 : 0);
        buf_u32(&enc, flags);
        if (off32) buf_u32(&enc, (uint32_t)e->offset); else buf_u64(&enc, (uint64_t)e->offset);
        if (us32) buf_u32(&enc, (uint32_t)e->usize); else buf_u64(&enc, (uint64_t)e->usize);
        if (e->method) {
            if (s32) buf_u32(&enc, (uint32_t)e->size); else buf_u64(&enc, (uint64_t)e->size);
            if (e->nblocks > 1) for (int k = 0; k < e->nblocks; k++) buf_u32(&enc, e->bsizes[k]);
        }
    }
    // path hash index
    buf phi = {0};
    buf_u32(&phi, (uint32_t)w->n);
    for (int i = 0; i < w->n; i++) { buf_u64(&phi, fnv64_path(w->e[i].path, 0)); buf_u32(&phi, (uint32_t)loc[i]); }
    buf_u32(&phi, 0);                                        // pruned directory index: empty
    // full directory index: "/" plus every directory (and its parents) with its files
    char **dirs = xmalloc(sizeof(char *) * (4 * w->n + 2));
    int nd = 0;
    dirs[nd++] = xstrdup("/");
    for (int i = 0; i < w->n; i++) {
        char *p = xstrdup(w->e[i].path);
        for (char *s = strrchr(p, '/'); s; s = strrchr(p, '/')) {
            s[1] = 0;
            int have = 0;
            for (int k = 0; k < nd; k++) have |= !strcmp(dirs[k], p);
            if (!have) dirs[nd++] = xstrdup(p);
            s[0] = 0;
        }
        free(p);
    }
    for (int a = 1; a < nd; a++)                             // sorted (ordinal), "/" first
        for (int b = a; b > 0 && strcmp(dirs[b - 1], dirs[b]) > 0; b--) { char *t = dirs[b]; dirs[b] = dirs[b - 1]; dirs[b - 1] = t; }
    buf fdi = {0};
    buf_u32(&fdi, (uint32_t)nd);
    for (int k = 0; k < nd; k++) {
        buf_fstring(&fdi, dirs[k]);
        int cnt = 0;
        for (int i = 0; i < w->n; i++) {
            const char *s = strrchr(w->e[i].path, '/');
            size_t dl = s ? (size_t)(s - w->e[i].path + 1) : 0;
            int in = !strcmp(dirs[k], "/") ? dl == 0 : (strlen(dirs[k]) == dl && !strncmp(dirs[k], w->e[i].path, dl));
            cnt += in;
        }
        buf_u32(&fdi, (uint32_t)cnt);
        for (int i = 0; i < w->n; i++) {
            const char *s = strrchr(w->e[i].path, '/');
            size_t dl = s ? (size_t)(s - w->e[i].path + 1) : 0;
            int in = !strcmp(dirs[k], "/") ? dl == 0 : (strlen(dirs[k]) == dl && !strncmp(dirs[k], w->e[i].path, dl));
            if (in) { buf_fstring(&fdi, w->e[i].path + dl); buf_u32(&fdi, (uint32_t)loc[i]); }
        }
        free(dirs[k]);
    }
    free(dirs);

    const char *mount = "../../../";
    size_t primary_size = 4 + strlen(mount) + 1 + 4 + 8 + 4 + (8 + 8 + 20) + 4 + (8 + 8 + 20) + 4 + enc.n + 4;
    int64_t index_off = w->pos, phi_off = index_off + (int64_t)primary_size, fdi_off = phi_off + (int64_t)phi.n;
    uint8_t h[20];
    buf pr = {0};
    buf_fstring(&pr, mount);
    buf_u32(&pr, (uint32_t)w->n);
    buf_u64(&pr, 0);                                         // path hash seed
    buf_u32(&pr, 1); buf_u64(&pr, (uint64_t)phi_off); buf_u64(&pr, phi.n); sha1(phi.p, phi.n, h); buf_put(&pr, h, 20);
    buf_u32(&pr, 1); buf_u64(&pr, (uint64_t)fdi_off); buf_u64(&pr, fdi.n); sha1(fdi.p, fdi.n, h); buf_put(&pr, h, 20);
    buf_u32(&pr, (uint32_t)enc.n); buf_put(&pr, enc.p, enc.n);
    buf_u32(&pr, 0);
    if (pr.n != primary_size) sr_fail("internal error: pak index size");
    wr(w, pr.p, pr.n);
    wr(w, phi.p, phi.n);
    wr(w, fdi.p, fdi.n);

    buf ft = {0};
    uint8_t zero[32] = {0};
    buf_put(&ft, zero, 16); buf_u8(&ft, 0);
    buf_u32(&ft, PAK_MAGIC); buf_u32(&ft, 11);
    buf_u64(&ft, (uint64_t)index_off); buf_u64(&ft, pr.n);
    sha1(pr.p, pr.n, h); buf_put(&ft, h, 20);
    char names[5 * 32] = {0};
    memcpy(names, "Zlib", 4);
    buf_put(&ft, names, sizeof names);
    wr(w, ft.p, ft.n);
    buf_free(&ft); buf_free(&pr); buf_free(&fdi); buf_free(&phi); buf_free(&enc);
    free(loc);
    for (int i = 0; i < w->n; i++) { free(w->e[i].path); free(w->e[i].bsizes); }
    free(w->e);
    if (!CloseHandle(w->h)) sr_fail("could not finish writing the registry pak");
    free(w);
}
