// Errors, buffers, files, log, hashes (CityHash64 v1.1 as used by UE's name batches, FNV-1a, SHA1 + AES via bcrypt).
#include "sr.h"

jmp_buf *sr_jmp;
char sr_error[1024];

void sr_fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(sr_error, sizeof sr_error, fmt, ap);
    va_end(ap);
    longjmp(*sr_jmp, 1);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) sr_fail("out of memory (%zu bytes)", n);
    return p;
}

void *xcalloc(size_t n, size_t m)
{
    void *p = calloc(n ? n : 1, m ? m : 1);
    if (!p) sr_fail("out of memory (%zu x %zu bytes)", n, m);
    return p;
}

void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p) sr_fail("out of memory (%zu bytes)", n);
    return p;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xmalloc(n), s, n);
}

// ---- buf

void buf_reserve(buf *b, size_t extra)
{
    if (b->n + extra <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->n + extra) cap += cap / 2 + extra;
    b->p = xrealloc(b->p, cap);
    b->cap = cap;
}

void buf_put(buf *b, const void *d, size_t n)
{
    buf_reserve(b, n);
    memcpy(b->p + b->n, d, n);
    b->n += n;
}

void buf_u8(buf *b, uint8_t v) { buf_put(b, &v, 1); }
void buf_u16be(buf *b, uint16_t v) { uint8_t t[2] = {v >> 8, v & 0xff}; buf_put(b, t, 2); }
void buf_u32(buf *b, uint32_t v) { buf_put(b, &v, 4); }
void buf_u64(buf *b, uint64_t v) { buf_put(b, &v, 8); }

void buf_fstring(buf *b, const char *s)
{
    uint32_t n = (uint32_t)strlen(s) + 1;
    buf_u32(b, n);
    buf_put(b, s, n);
}

void buf_free(buf *b)
{
    free(b->p);
    b->p = NULL; b->n = b->cap = 0;
}

// ---- rd

void rd_need(rd *r, size_t n)
{
    if (r->at > r->n || n > r->n - r->at) sr_fail("truncated data (need %zu bytes at %zu of %zu)", n, r->at, r->n);
}

uint8_t rd_u8(rd *r) { rd_need(r, 1); return r->p[r->at++]; }
uint32_t rd_u32(rd *r) { rd_need(r, 4); uint32_t v = rd32(r->p + r->at); r->at += 4; return v; }
int32_t rd_i32(rd *r) { return (int32_t)rd_u32(r); }
uint64_t rd_u64(rd *r) { rd_need(r, 8); uint64_t v = rd64(r->p + r->at); r->at += 8; return v; }
void rd_skip(rd *r, size_t n) { rd_need(r, n); r->at += n; }

void rd_skip_fstring(rd *r)
{
    int32_t len = rd_i32(r);
    if (len < -(1 << 24) || len > (1 << 25)) sr_fail("bad string length %d", len);
    rd_skip(r, len < 0 ? (size_t)(-2 * (int64_t)len) : (size_t)len);
}

char *rd_fstring(rd *r)
{
    int32_t len = rd_i32(r);
    if (len < -(1 << 24) || len > (1 << 25)) sr_fail("bad string length %d", len);
    if (len >= 0) {
        rd_need(r, len);
        char *s = xmalloc(len + 1);
        memcpy(s, r->p + r->at, len);
        s[len] = 0;
        r->at += len;
        return s;
    }
    size_t n = (size_t)(-len);
    rd_need(r, 2 * n);
    wchar_t *w = xmalloc(2 * n + 2);
    memcpy(w, r->p + r->at, 2 * n);
    w[n] = 0;
    r->at += 2 * n;
    char *s = w_to_utf8(w);
    free(w);
    return s;
}

// ---- files / strings

uint8_t *file_read_all(const wchar_t *path, size_t *n)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > 0x7fffffff) { CloseHandle(h); return NULL; }
    uint8_t *p = xmalloc((size_t)sz.QuadPart + 1);
    DWORD got = 0;
    if (!ReadFile(h, p, (DWORD)sz.QuadPart, &got, NULL) || got != sz.QuadPart) { CloseHandle(h); free(p); return NULL; }
    CloseHandle(h);
    p[got] = 0;
    *n = got;
    return p;
}

wchar_t *wpath(const wchar_t *a, const wchar_t *b)
{
    size_t na = wcslen(a), nb = wcslen(b);
    wchar_t *p = xmalloc((na + nb + 2) * sizeof(wchar_t));
    memcpy(p, a, na * sizeof(wchar_t));
    if (na && a[na - 1] != L'\\' && a[na - 1] != L'/') p[na++] = L'\\';
    memcpy(p + na, b, (nb + 1) * sizeof(wchar_t));
    return p;
}

wchar_t *utf8_to_w(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = xmalloc((n + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    w[n] = 0;
    return w;
}

char *w_to_utf8(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = xmalloc(n + 1);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    s[n] = 0;
    return s;
}

const wchar_t *data_dir(void)
{
    static wchar_t dir[MAX_PATH + 64];
    if (dir[0]) return dir;
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", dir, MAX_PATH);
    if (!n || n >= MAX_PATH) n = GetTempPathW(MAX_PATH, dir);
    if (n && dir[n - 1] != L'\\') dir[n++] = L'\\';
    wcscpy(dir + n, DATA_DIR_NAME);
    CreateDirectoryW(dir, NULL);
    return dir;
}

// ---- log

static HANDLE log_file = INVALID_HANDLE_VALUE;
static HANDLE console_out = NULL;

void log_open(void)
{
    if (log_file != INVALID_HANDLE_VALUE) return;
    wchar_t *p = wpath(data_dir(), L"SuitRegistry.log");
    WIN32_FILE_ATTRIBUTE_DATA a;
    if (GetFileAttributesExW(p, GetFileExInfoStandard, &a) && (a.nFileSizeHigh || a.nFileSizeLow > (1u << 20)))
        DeleteFileW(p);
    log_file = CreateFileW(p, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    free(p);
    SYSTEMTIME t;
    GetLocalTime(&t);
    log_msg("--- %04d-%02d-%02d %02d:%02d:%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
}

void log_msg(const char *fmt, ...)
{
    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof line - 3) n = sizeof line - 3;
    line[n++] = '\r'; line[n++] = '\n'; line[n] = 0;
    DWORD w;
    if (log_file != INVALID_HANDLE_VALUE) WriteFile(log_file, line, n, &w, NULL);
    if (console_out) {
        wchar_t *ws = utf8_to_w(line);
        WriteConsoleW(console_out, ws, (DWORD)wcslen(ws), &w, NULL);
        free(ws);
    }
}

void console_show(void)
{
    if (console_out) return;
    if (!AllocConsole()) AttachConsole(ATTACH_PARENT_PROCESS);
    SetConsoleTitleW(L"Midnight Suns suit registry");
    console_out = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (console_out == INVALID_HANDLE_VALUE) console_out = NULL;
    if (console_out) {
        DWORD w;
        WriteConsoleW(console_out, L"Updating the suit registry, the game starts right after...\r\n", 60, &w, NULL);
    }
}

// ---- FNV-1a

uint64_t fnv1a64(const void *p, size_t n)
{
    const uint8_t *s = p;
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) { h ^= s[i]; h *= 0x100000001b3ull; }
    return h;
}

// ---- CityHash64 (v1.1)

static const uint64_t k0 = 0xc3a5c85c97cb3127ull, k1 = 0xb492b66fbe98f273ull, k2 = 0x9ae16a3b2f90404full;
static inline uint64_t rot(uint64_t v, int s) { return s == 0 ? v : (v >> s) | (v << (64 - s)); }
static inline uint64_t smix(uint64_t v) { return v ^ (v >> 47); }
static inline uint64_t f64(const uint8_t *p) { return rd64(p); }
static inline uint64_t f32(const uint8_t *p) { return rd32(p); }

static uint64_t hl16m(uint64_t u, uint64_t v, uint64_t mul)
{
    uint64_t a = (u ^ v) * mul;
    a ^= a >> 47;
    uint64_t b = (v ^ a) * mul;
    b ^= b >> 47;
    return b * mul;
}

static uint64_t hl16(uint64_t u, uint64_t v) { return hl16m(u, v, 0x9ddfea08eb382d69ull); }

static uint64_t hl0to16(const uint8_t *s, size_t len)
{
    if (len >= 8) {
        uint64_t mul = k2 + len * 2, a = f64(s) + k2, b = f64(s + len - 8);
        uint64_t c = rot(b, 37) * mul + a, d = (rot(a, 25) + b) * mul;
        return hl16m(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2, a = f32(s);
        return hl16m(len + (a << 3), f32(s + len - 4), mul);
    }
    if (len > 0) {
        uint8_t a = s[0], b = s[len >> 1], c = s[len - 1];
        uint32_t y = (uint32_t)a + ((uint32_t)b << 8), z = (uint32_t)len + ((uint32_t)c << 2);
        return smix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

static uint64_t hl17to32(const uint8_t *s, size_t len)
{
    uint64_t mul = k2 + len * 2, a = f64(s) * k1, b = f64(s + 8), c = f64(s + len - 8) * mul, d = f64(s + len - 16) * k2;
    return hl16m(rot(a + b, 43) + rot(c, 30) + d, a + rot(b + k2, 18) + c, mul);
}

static uint64_t hl33to64(const uint8_t *s, size_t len)
{
    uint64_t mul = k2 + len * 2, a = f64(s) * k2, b = f64(s + 8), c = f64(s + len - 24), d = f64(s + len - 32);
    uint64_t e = f64(s + 16) * k2, f = f64(s + 24) * 9, g = f64(s + len - 8), h = f64(s + len - 16) * mul;
    uint64_t u = rot(a + g, 43) + (rot(b, 30) + c) * 9, v = ((a + g) ^ d) + f + 1;
    uint64_t w = __builtin_bswap64((u + v) * mul) + h, x = rot(e + f, 42) + c;
    uint64_t y = (__builtin_bswap64((v + w) * mul) + g) * mul, z = e + f + c;
    a = __builtin_bswap64((x + z) * mul + y) + b;
    b = smix((z + a) * mul + d + h) * mul;
    return b + x;
}

typedef struct { uint64_t first, second; } u128;

static u128 weak32(const uint8_t *s, uint64_t a, uint64_t b)
{
    uint64_t w = f64(s), x = f64(s + 8), y = f64(s + 16), z = f64(s + 24);
    a += w;
    b = rot(b + a + z, 21);
    uint64_t c = a;
    a += x;
    a += y;
    b += rot(a, 44);
    return (u128){a + z, b + c};
}

uint64_t city_hash64(const uint8_t *s, size_t len)
{
    if (len <= 32) return len <= 16 ? hl0to16(s, len) : hl17to32(s, len);
    if (len <= 64) return hl33to64(s, len);
    uint64_t x = f64(s + len - 40), y = f64(s + len - 16) + f64(s + len - 56);
    uint64_t z = hl16(f64(s + len - 48) + len, f64(s + len - 24));
    u128 v = weak32(s + len - 64, len, z), w = weak32(s + len - 32, y + k1, x);
    x = x * k1 + f64(s);
    len = (len - 1) & ~(size_t)63;
    do {
        x = rot(x + y + v.first + f64(s + 8), 37) * k1;
        y = rot(y + v.second + f64(s + 48), 42) * k1;
        x ^= w.second;
        y += v.first + f64(s + 40);
        z = rot(z + w.first, 33) * k1;
        v = weak32(s, v.second * k1, x + w.first);
        w = weak32(s + 32, z + w.second, y + f64(s + 16));
        uint64_t t = z; z = x; x = t;
        s += 64;
        len -= 64;
    } while (len != 0);
    return hl16(hl16(v.first, w.first) + smix(y) * k1 + z, hl16(v.second, w.second) + x);
}

// ---- bcrypt (loaded on demand, never in DllMain)

typedef LONG (WINAPI *open_alg_t)(void **, LPCWSTR, LPCWSTR, ULONG);
typedef LONG (WINAPI *create_hash_t)(void *, void **, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *hash_data_t)(void *, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *finish_hash_t)(void *, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *destroy_t)(void *);
typedef LONG (WINAPI *set_prop_t)(void *, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *gen_key_t)(void *, void **, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *decrypt_t)(void *, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);

static struct {
    int loaded;
    open_alg_t open_alg; create_hash_t create_hash; hash_data_t hash_data; finish_hash_t finish_hash;
    destroy_t destroy_hash, destroy_key; set_prop_t set_prop; gen_key_t gen_key; decrypt_t decrypt;
} bc;

static void bcrypt_load(void)
{
    if (bc.loaded) return;
    HMODULE m = LoadLibraryW(L"bcrypt.dll");
    if (!m) sr_fail("bcrypt.dll could not be loaded");
    bc.open_alg = (open_alg_t)GetProcAddress(m, "BCryptOpenAlgorithmProvider");
    bc.create_hash = (create_hash_t)GetProcAddress(m, "BCryptCreateHash");
    bc.hash_data = (hash_data_t)GetProcAddress(m, "BCryptHashData");
    bc.finish_hash = (finish_hash_t)GetProcAddress(m, "BCryptFinishHash");
    bc.destroy_hash = (destroy_t)GetProcAddress(m, "BCryptDestroyHash");
    bc.destroy_key = (destroy_t)GetProcAddress(m, "BCryptDestroyKey");
    bc.set_prop = (set_prop_t)GetProcAddress(m, "BCryptSetProperty");
    bc.gen_key = (gen_key_t)GetProcAddress(m, "BCryptGenerateSymmetricKey");
    bc.decrypt = (decrypt_t)GetProcAddress(m, "BCryptDecrypt");
    if (!bc.open_alg || !bc.create_hash || !bc.hash_data || !bc.finish_hash || !bc.destroy_hash || !bc.destroy_key ||
        !bc.set_prop || !bc.gen_key || !bc.decrypt)
        sr_fail("bcrypt.dll is missing functions");
    bc.loaded = 1;
}

struct sha1_ctx { void *alg, *h; };

sha1_ctx *sha1_begin(void)
{
    bcrypt_load();
    sha1_ctx *c = xcalloc(1, sizeof *c);
    if (bc.open_alg(&c->alg, L"SHA1", NULL, 0) || bc.create_hash(c->alg, &c->h, NULL, 0, NULL, 0, 0))
        sr_fail("SHA1 is not available");
    return c;
}

void sha1_add(sha1_ctx *c, const void *p, size_t n)
{
    const uint8_t *s = p;
    while (n) {
        ULONG k = n > 0x40000000 ? 0x40000000 : (ULONG)n;
        bc.hash_data(c->h, (PUCHAR)s, k, 0);
        s += k; n -= k;
    }
}

void sha1_end(sha1_ctx *c, uint8_t out[20])
{
    bc.finish_hash(c->h, out, 20, 0);
    bc.destroy_hash(c->h);
    free(c);                                                // (the algorithm handle is cached by bcrypt)
}

void sha1(const void *p, size_t n, uint8_t out[20])
{
    sha1_ctx *c = sha1_begin();
    sha1_add(c, p, n);
    sha1_end(c, out);
}

int aes_available(void) { return 1; }

void aes256_ecb_decrypt(const uint8_t key[32], uint8_t *p, size_t n)
{
    bcrypt_load();
    static void *alg, *k;
    if (!alg) {
        if (bc.open_alg(&alg, L"AES", NULL, 0)) sr_fail("AES is not available");
        static const wchar_t ecb[] = L"ChainingModeECB";
        if (bc.set_prop(alg, L"ChainingMode", (PUCHAR)ecb, sizeof ecb, 0)) sr_fail("AES-ECB is not available");
        if (bc.gen_key(alg, &k, NULL, 0, (PUCHAR)key, 32, 0)) sr_fail("AES key rejected");
    }
    ULONG got;
    for (size_t at = 0; at < n;) {
        ULONG k2n = (n - at) > 0x40000000 ? 0x40000000 : (ULONG)(n - at);
        if (bc.decrypt(k, p + at, k2n, NULL, NULL, 0, p + at, k2n, &got, 0)) sr_fail("AES decryption failed");
        at += k2n;
    }
}
