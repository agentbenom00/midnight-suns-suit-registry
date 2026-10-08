// Deflate decoder (stored/fixed/dynamic blocks) and a compact deflate encoder: LZ77 with hash chains and lazy
// matching, one dynamic-Huffman block per call (pak blocks are 64 KiB), zlib framing for pak entries.
#include "sr.h"

// ================================================================ inflate

typedef struct { const uint8_t *in; size_t n, at; uint32_t bits; int nbits; } bitin;

static int need_bits(bitin *b, int k)
{
    while (b->nbits < k) {
        if (b->at >= b->n) return -1;
        b->bits |= (uint32_t)b->in[b->at++] << b->nbits;
        b->nbits += 8;
    }
    return 0;
}

static int get_bits(bitin *b, int k, uint32_t *v)
{
    if (k == 0) { *v = 0; return 0; }
    if (need_bits(b, k)) return -1;
    *v = b->bits & ((1u << k) - 1);
    b->bits >>= k;
    b->nbits -= k;
    return 0;
}

typedef struct { uint16_t count[16]; uint16_t sym[288]; } huff;

static int huff_build(huff *h, const uint8_t *lens, int n)
{
    uint16_t offs[16];
    memset(h->count, 0, sizeof h->count);
    for (int i = 0; i < n; i++) h->count[lens[i]]++;
    h->count[0] = 0;
    int left = 1;
    for (int i = 1; i < 16; i++) {
        left <<= 1;
        left -= h->count[i];
        if (left < 0) return -1;
    }
    offs[1] = 0;
    for (int i = 1; i < 15; i++) offs[i + 1] = offs[i] + h->count[i];
    for (int i = 0; i < n; i++)
        if (lens[i]) h->sym[offs[lens[i]]++] = (uint16_t)i;
    return 0;
}

static int huff_decode(bitin *b, const huff *h)
{
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; len++) {
        uint32_t bit;
        if (get_bits(b, 1, &bit)) return -1;
        code |= (int)bit;
        int count = h->count[len];
        if (code - count < first) return h->sym[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static const uint16_t len_base[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
                                      115, 131, 163, 195, 227, 258};
static const uint8_t len_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t dist_base[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
                                       1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
                                       12, 13, 13};

int inflate_raw(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, size_t *consumed)
{
    bitin b = {in, inlen, 0, 0, 0};
    size_t o = 0;
    uint32_t last, type;
    huff lit, dist;
    do {
        if (get_bits(&b, 1, &last) || get_bits(&b, 2, &type)) return -1;
        if (type == 0) {
            b.bits = 0; b.nbits = 0;                        // byte align
            if (b.at + 4 > b.n) return -1;
            uint32_t len = in[b.at] | in[b.at + 1] << 8, nlen = in[b.at + 2] | in[b.at + 3] << 8;
            b.at += 4;
            if ((len ^ 0xffff) != nlen || b.at + len > b.n || o + len > outlen) return -1;
            memcpy(out + o, in + b.at, len);
            b.at += len; o += len;
            continue;
        }
        if (type == 1) {
            uint8_t l[320];
            int i = 0;
            for (; i < 144; i++) l[i] = 8;
            for (; i < 256; i++) l[i] = 9;
            for (; i < 280; i++) l[i] = 7;
            for (; i < 288; i++) l[i] = 8;
            huff_build(&lit, l, 288);
            for (i = 0; i < 30; i++) l[i] = 5;
            huff_build(&dist, l, 30);
        } else if (type == 2) {
            uint32_t hlit, hdist, hclen;
            if (get_bits(&b, 5, &hlit) || get_bits(&b, 5, &hdist) || get_bits(&b, 4, &hclen)) return -1;
            hlit += 257; hdist += 1; hclen += 4;
            static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            uint8_t cl[19] = {0}, l[320] = {0};
            for (uint32_t i = 0; i < hclen; i++) {
                uint32_t v;
                if (get_bits(&b, 3, &v)) return -1;
                cl[order[i]] = (uint8_t)v;
            }
            huff clh;
            if (huff_build(&clh, cl, 19)) return -1;
            uint32_t i = 0;
            while (i < hlit + hdist) {
                int s = huff_decode(&b, &clh);
                if (s < 0) return -1;
                if (s < 16) { l[i++] = (uint8_t)s; continue; }
                uint32_t rep, v = 0;
                uint8_t val = 0;
                if (s == 16) {
                    if (i == 0 || get_bits(&b, 2, &rep)) return -1;
                    val = l[i - 1]; rep += 3;
                } else if (s == 17) {
                    if (get_bits(&b, 3, &rep)) return -1;
                    rep += 3;
                } else {
                    if (get_bits(&b, 7, &rep)) return -1;
                    rep += 11;
                }
                (void)v;
                if (i + rep > hlit + hdist) return -1;
                while (rep--) l[i++] = val;
            }
            if (huff_build(&lit, l, hlit) && hlit > 1) return -1;
            if (huff_build(&dist, l + hlit, hdist) && hdist > 1) return -1;
        } else return -1;
        for (;;) {
            int s = huff_decode(&b, &lit);
            if (s < 0) return -1;
            if (s < 256) {
                if (o >= outlen) return -1;
                out[o++] = (uint8_t)s;
            } else if (s == 256) break;
            else {
                s -= 257;
                if (s >= 29) return -1;
                uint32_t e, len, d;
                if (get_bits(&b, len_extra[s], &e)) return -1;
                len = len_base[s] + e;
                int ds = huff_decode(&b, &dist);
                if (ds < 0 || ds >= 30) return -1;
                if (get_bits(&b, dist_extra[ds], &e)) return -1;
                d = dist_base[ds] + e;
                if (d > o || o + len > outlen) return -1;
                uint8_t *p = out + o;
                const uint8_t *q = p - d;
                for (uint32_t k = 0; k < len; k++) p[k] = q[k];
                o += len;
            }
        }
    } while (!last);
    if (o != outlen) return -1;
    if (consumed) *consumed = b.at;
    return 0;
}

int inflate_zlib(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    if (inlen < 6 || (in[0] & 0x0f) != 8 || ((in[0] << 8) | in[1]) % 31 || (in[1] & 0x20)) return -1;
    return inflate_raw(in + 2, inlen - 2, out, outlen, NULL);
}

// ================================================================ deflate

typedef struct { uint8_t *out; size_t cap, n; uint64_t bits; int nbits; int overflow; } bitout;

static void put_bits(bitout *b, uint32_t v, int k)
{
    b->bits |= (uint64_t)v << b->nbits;
    b->nbits += k;
    while (b->nbits >= 8) {
        if (b->n < b->cap) b->out[b->n++] = (uint8_t)b->bits; else b->overflow = 1;
        b->bits >>= 8;
        b->nbits -= 8;
    }
}

static void flush_bits(bitout *b)
{
    if (b->nbits > 0) put_bits(b, 0, 8 - b->nbits);
}

static uint32_t rev_bits(uint32_t v, int k)
{
    uint32_t r = 0;
    for (int i = 0; i < k; i++) { r = (r << 1) | (v & 1); v >>= 1; }
    return r;
}

// Huffman code lengths limited to maxlen (heap-free: sort by frequency, compute optimal lengths with the
// in-place Moffat-Katajainen algorithm, then enforce the limit as miniz does).
typedef struct { uint32_t f; uint16_t s; } fsym;

static int cmp_fsym(const void *a, const void *b)
{
    const fsym *x = a, *y = b;
    if (x->f != y->f) return x->f < y->f ? -1 : 1;
    return x->s < y->s ? -1 : 1;
}

static void huff_lengths(const uint32_t *freq, int n, int maxlen, uint8_t *lens)
{
    fsym sy[320];
    int m = 0;
    memset(lens, 0, n);
    for (int i = 0; i < n; i++)
        if (freq[i]) sy[m++] = (fsym){freq[i], (uint16_t)i};
    if (m == 0) return;
    if (m == 1) { lens[sy[0].s] = 1; return; }
    qsort(sy, m, sizeof *sy, cmp_fsym);
    // Moffat-Katajainen in place: A[i] = frequencies ascending -> code lengths
    uint32_t A[320];
    for (int i = 0; i < m; i++) A[i] = sy[i].f;
    {
        int root, leaf, next, avbl, used, dpth;
        A[0] += A[1];
        root = 0; leaf = 2;
        for (next = 1; next < m - 1; next++) {
            if (leaf >= m || A[root] < A[leaf]) { A[next] = A[root]; A[root++] = next; }
            else A[next] = A[leaf++];
            if (leaf >= m || (root < next && A[root] < A[leaf])) { A[next] += A[root]; A[root++] = next; }
            else A[next] += A[leaf++];
        }
        A[m - 2] = 0;
        for (next = m - 3; next >= 0; next--) A[next] = A[A[next]] + 1;
        avbl = 1; used = dpth = 0; root = m - 2; next = m - 1;
        while (avbl > 0) {
            while (root >= 0 && (int)A[root] == dpth) { used++; root--; }
            while (avbl > used) { A[next--] = dpth; avbl--; }
            avbl = 2 * used; dpth++; used = 0;
        }
    }
    // A[i] is now the length of the i-th least frequent symbol; enforce maxlen
    int count[33] = {0};
    for (int i = 0; i < m; i++) count[A[i] > 32 ? 32 : A[i]]++;
    for (int i = maxlen + 1; i <= 32; i++) { count[maxlen] += count[i]; count[i] = 0; }
    uint32_t total = 0;
    for (int i = maxlen; i > 0; i--) total += (uint32_t)count[i] << (maxlen - i);
    while (total != (1u << maxlen)) {
        count[maxlen]--;
        for (int i = maxlen - 1; i > 0; i--)
            if (count[i]) { count[i]--; count[i + 1] += 2; break; }
        total--;
    }
    // longest codes to the least frequent symbols
    int k = 0;
    for (int len = maxlen; len > 0; len--)
        for (int c = count[len]; c > 0; c--) lens[sy[k++].s] = (uint8_t)len;
}

static void huff_codes(const uint8_t *lens, int n, uint16_t *codes)
{
    int count[16] = {0}, next[16];
    for (int i = 0; i < n; i++) count[lens[i]]++;
    count[0] = 0;
    int code = 0;
    for (int b = 1; b < 16; b++) { code = (code + count[b - 1]) << 1; next[b] = code; }
    for (int i = 0; i < n; i++)
        if (lens[i]) codes[i] = (uint16_t)rev_bits(next[lens[i]]++, lens[i]);
}

static int len_code(int len)
{
    int c = 0;
    while (c < 28 && len_base[c + 1] <= len) c++;
    return c;
}

static int dist_code(int d)
{
    int c = 0;
    while (c < 29 && dist_base[c + 1] <= d) c++;
    return c;
}

#define WBITS 15
#define WSIZE (1 << WBITS)
#define HBITS 15
#define MAXCHAIN 48

size_t deflate_bound(size_t n) { return n + n / 1000 + 64 + 5 * (n / 16000 + 1); }      // (stored fallback fits)

size_t deflate_zlib(const uint8_t *in, size_t n, uint8_t *out, size_t outcap)
{
    // tokens: literal (dist 0) or match
    typedef struct { uint16_t len, dist; } tok;
    tok *toks = malloc((n + 1) * sizeof(tok));
    int32_t *head = malloc(sizeof(int32_t) << HBITS), *prev = malloc(sizeof(int32_t) * (n + 1));
    if (!toks || !head || !prev) { free(toks); free(head); free(prev); return 0; }
    memset(head, 0xff, sizeof(int32_t) << HBITS);
    size_t nt = 0;
#define HASH3(p) ((((uint32_t)(p)[0] << 10) ^ ((uint32_t)(p)[1] << 5) ^ (p)[2]) & ((1 << HBITS) - 1))
    size_t i = 0;
    while (i < n) {
        int best = 0, bestd = 0;
        if (i + 3 <= n) {
            uint32_t h = HASH3(in + i);
            int32_t c = head[h];
            prev[i] = c;
            head[h] = (int32_t)i;
            int chain = MAXCHAIN, maxlen = (int)((n - i) < 258 ? (n - i) : 258);
            while (c >= 0 && i - c <= WSIZE - 262 && chain--) {
                if (in[c + best] == in[i + best] && in[c] == in[i]) {
                    int l = 0;
                    while (l < maxlen && in[c + l] == in[i + l]) l++;
                    if (l > best) { best = l; bestd = (int)(i - c); if (l == maxlen) break; }
                }
                c = prev[c];
            }
        }
        if (best >= 3) {
            // lazy: is a longer match one byte later?
            if (best < 32 && i + 4 <= n) {
                size_t j = i + 1;
                uint32_t h = HASH3(in + j);
                int32_t c = head[h];
                int chain = MAXCHAIN / 2, maxlen = (int)((n - j) < 258 ? (n - j) : 258), b2 = 0;
                while (c >= 0 && j - c <= WSIZE - 262 && chain--) {
                    if (in[c + b2] == in[j + b2]) {
                        int l = 0;
                        while (l < maxlen && in[c + l] == in[j + l]) l++;
                        if (l > b2) b2 = l;
                    }
                    c = prev[c];
                }
                if (b2 > best + 1) { toks[nt++] = (tok){in[i], 0}; i++; continue; }
            }
            toks[nt++] = (tok){(uint16_t)best, (uint16_t)bestd};
            for (size_t k = i + 1; k < i + best; k++)               // insert the skipped positions
                if (k + 3 <= n) { uint32_t h = HASH3(in + k); prev[k] = head[h]; head[h] = (int32_t)k; }
            i += best;
        } else {
            toks[nt++] = (tok){in[i], 0};
            i++;
        }
    }
    free(head); free(prev);

    uint32_t lf[286] = {0}, df[30] = {0};
    for (size_t t = 0; t < nt; t++) {
        if (toks[t].dist == 0) lf[toks[t].len]++;
        else { lf[257 + len_code(toks[t].len)]++; df[dist_code(toks[t].dist)]++; }
    }
    lf[256] = 1;
    int ndist_used = 0;
    for (int k = 0; k < 30; k++) ndist_used += df[k] != 0;
    if (ndist_used < 2) { df[0] += 1; df[1] += 1; }                 // keep the distance tree valid for old decoders
    uint8_t ll[286], dl[30];
    uint16_t lc[286], dc[30];
    huff_lengths(lf, 286, 15, ll);
    huff_lengths(df, 30, 15, dl);
    huff_codes(ll, 286, lc);
    huff_codes(dl, 30, dc);
    int hlit = 286, hdist = 30;
    while (hlit > 257 && !ll[hlit - 1]) hlit--;
    while (hdist > 1 && !dl[hdist - 1]) hdist--;

    // code-length sequence with run-length codes 16/17/18
    uint8_t all[316], rl[316], rx[316];
    int na = 0, nr = 0;
    memcpy(all, ll, hlit); memcpy(all + hlit, dl, hdist); na = hlit + hdist;
    for (int k = 0; k < na;) {
        int r = 1;
        while (k + r < na && all[k + r] == all[k]) r++;
        if (all[k] == 0 && r >= 3) {
            int c = r > 138 ? 138 : r;
            if (c >= 11) { rl[nr] = 18; rx[nr++] = (uint8_t)(c - 11); } else { rl[nr] = 17; rx[nr++] = (uint8_t)(c - 3); }
            k += c;
        } else if (r >= 4) {
            rl[nr] = all[k]; rx[nr++] = 0;
            int c = r - 1 > 6 ? 6 : r - 1;
            rl[nr] = 16; rx[nr++] = (uint8_t)(c - 3);
            k += 1 + c;
        } else { rl[nr] = all[k]; rx[nr++] = 0; k++; }
    }
    uint32_t cf[19] = {0};
    for (int k = 0; k < nr; k++) cf[rl[k]]++;
    uint8_t cll[19];
    uint16_t clc[19];
    huff_lengths(cf, 19, 7, cll);
    huff_codes(cll, 19, clc);
    static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    int hclen = 19;
    while (hclen > 4 && !cll[order[hclen - 1]]) hclen--;

    bitout b = {out, outcap, 0, 0, 0, 0};
    put_bits(&b, 0x78, 8); put_bits(&b, 0x9c, 8);                     // zlib header
    put_bits(&b, 1, 1); put_bits(&b, 2, 2);                            // final, dynamic
    put_bits(&b, hlit - 257, 5); put_bits(&b, hdist - 1, 5); put_bits(&b, hclen - 4, 4);
    for (int k = 0; k < hclen; k++) put_bits(&b, cll[order[k]], 3);
    for (int k = 0; k < nr; k++) {
        put_bits(&b, clc[rl[k]], cll[rl[k]]);
        if (rl[k] == 16) put_bits(&b, rx[k], 2);
        else if (rl[k] == 17) put_bits(&b, rx[k], 3);
        else if (rl[k] == 18) put_bits(&b, rx[k], 7);
    }
    for (size_t t = 0; t < nt && !b.overflow; t++) {
        if (toks[t].dist == 0) { put_bits(&b, lc[toks[t].len], ll[toks[t].len]); continue; }
        int L = toks[t].len, D = toks[t].dist, l = len_code(L), d = dist_code(D);
        put_bits(&b, lc[257 + l], ll[257 + l]);
        if (len_extra[l]) put_bits(&b, L - len_base[l], len_extra[l]);
        put_bits(&b, dc[d], dl[d]);
        if (dist_extra[d]) put_bits(&b, D - dist_base[d], dist_extra[d]);
    }
    put_bits(&b, lc[256], ll[256]);
    flush_bits(&b);
    free(toks);
    uint32_t a = 1, s2 = 0;                                            // adler32
    for (size_t k = 0; k < n;) {
        size_t e = k + 5552 < n ? k + 5552 : n;
        for (; k < e; k++) { a += in[k]; s2 += a; }
        a %= 65521; s2 %= 65521;
    }
    uint32_t ad = (s2 << 16) | a;
    for (int k = 3; k >= 0; k--) put_bits(&b, (ad >> (8 * k)) & 0xff, 8);
    if (!b.overflow) return b.n;
    // incompressible: stored blocks
    size_t o = 0, need = 2 + n + 5 * (n / 65535 + 1) + 4;
    if (need > outcap) return 0;
    out[o++] = 0x78; out[o++] = 0x01;
    size_t k = 0;
    do {
        size_t c = n - k > 65535 ? 65535 : n - k;
        out[o++] = k + c >= n;
        out[o++] = c & 0xff; out[o++] = c >> 8; out[o++] = ~c & 0xff; out[o++] = (~c >> 8) & 0xff;
        memcpy(out + o, in + k, c);
        o += c; k += c;
    } while (k < n);
    for (int q = 3; q >= 0; q--) out[o++] = (ad >> (8 * q)) & 0xff;
    return o;
}
