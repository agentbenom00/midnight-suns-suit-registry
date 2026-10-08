// Oodle (the game's language registries are Oodle-compressed). Looked for next to this DLL and in the data folder;
// otherwise downloaded once from the OodleUE builds on GitHub (what FModel / CUE4Parse use) and cached.
#include "sr.h"

#define OODLE_HOST L"github.com"
#define OODLE_URL L"/WorkingRobot/OodleUE/releases/download/2026-06-04-1357/clang-cl-x64-release.zip"
#define OODLE_ZIP_ENTRY "bin/oodle-data-shared.dll"

typedef intptr_t (WINAPI *decompress_t)(const void *, intptr_t, void *, intptr_t, int, int, int, void *, intptr_t,
                                        void *, void *, void *, intptr_t, int);
static decompress_t decompress;
extern HINSTANCE sr_self;

static int try_load(const wchar_t *path)
{
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return 0;
    HMODULE m = LoadLibraryW(path);
    if (!m) return 0;
    decompress = (decompress_t)GetProcAddress(m, "OodleLZ_Decompress");
    return decompress != NULL;
}

// ---- download

typedef void *HINTERNET_;
typedef HINTERNET_ (WINAPI *open_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET_ (WINAPI *connect_t)(HINTERNET_, LPCWSTR, WORD, DWORD);
typedef HINTERNET_ (WINAPI *open_req_t)(HINTERNET_, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL (WINAPI *send_t)(HINTERNET_, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *recv_t)(HINTERNET_, LPVOID);
typedef BOOL (WINAPI *query_t)(HINTERNET_, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *read_t)(HINTERNET_, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *close_t)(HINTERNET_);

static uint8_t *http_get(const wchar_t *host, const wchar_t *path, size_t *n)
{
    HMODULE m = LoadLibraryW(L"winhttp.dll");
    if (!m) sr_fail("winhttp.dll could not be loaded");
    open_t o = (open_t)GetProcAddress(m, "WinHttpOpen");
    connect_t c = (connect_t)GetProcAddress(m, "WinHttpConnect");
    open_req_t orq = (open_req_t)GetProcAddress(m, "WinHttpOpenRequest");
    send_t s = (send_t)GetProcAddress(m, "WinHttpSendRequest");
    recv_t rc = (recv_t)GetProcAddress(m, "WinHttpReceiveResponse");
    query_t q = (query_t)GetProcAddress(m, "WinHttpQueryHeaders");
    read_t rdd = (read_t)GetProcAddress(m, "WinHttpReadData");
    close_t cl = (close_t)GetProcAddress(m, "WinHttpCloseHandle");
    if (!o || !c || !orq || !s || !rc || !q || !rdd || !cl) sr_fail("winhttp.dll is missing functions");
    HINTERNET_ ses = o(L"MidnightSunsSuitRegistry/2", 4 /* automatic proxy */, NULL, NULL, 0);
    if (!ses) ses = o(L"MidnightSunsSuitRegistry/2", 0 /* default proxy */, NULL, NULL, 0);
    if (!ses) sr_fail("no internet access (WinHttpOpen failed)");
    HINTERNET_ con = c(ses, host, 443, 0);
    HINTERNET_ req = con ? orq(con, L"GET", path, NULL, NULL, NULL, 0x00800000 /* secure */) : NULL;
    if (!req || !s(req, NULL, 0, NULL, 0, 0, 0) || !rc(req, NULL)) {
        DWORD e = GetLastError();
        if (req) cl(req);
        if (con) cl(con);
        cl(ses);
        sr_fail("download failed (error %lu) - is the computer online?", e);
    }
    DWORD status = 0, len = sizeof status;
    q(req, 19 | 0x20000000 /* status code, as number */, NULL, &status, &len, NULL);
    buf b = {0};
    if (status == 200) {
        for (;;) {
            buf_reserve(&b, 1 << 16);
            DWORD got = 0;
            if (!rdd(req, b.p + b.n, 1 << 16, &got)) { status = 0; break; }
            if (!got) break;
            b.n += got;
        }
    }
    cl(req); cl(con); cl(ses);
    if (status != 200) { buf_free(&b); sr_fail("download failed (HTTP %lu)", status); }
    *n = b.n;
    return b.p;
}

static uint8_t *zip_extract(const uint8_t *z, size_t n, const char *want, size_t *outn)
{
    if (n < 22) return NULL;
    size_t e = n - 22;
    while (e > 0 && rd32(z + e) != 0x06054b50) e--;
    if (rd32(z + e) != 0x06054b50) return NULL;
    uint32_t count = rd16(z + e + 10), cd = rd32(z + e + 16);
    size_t at = cd;
    for (uint32_t i = 0; i < count && at + 46 <= n; i++) {
        if (rd32(z + at) != 0x02014b50) return NULL;
        uint16_t method = rd16(z + at + 10), nl = rd16(z + at + 28), xl = rd16(z + at + 30), cl = rd16(z + at + 32);
        uint32_t csize = rd32(z + at + 20), usize = rd32(z + at + 24), lho = rd32(z + at + 42);
        if (at + 46 + nl > n) return NULL;
        if (nl == strlen(want) && !memcmp(z + at + 46, want, nl)) {
            if (lho + 30 > n || rd32(z + lho) != 0x04034b50) return NULL;
            size_t data = lho + 30 + rd16(z + lho + 26) + rd16(z + lho + 28);
            if (data + csize > n) return NULL;
            uint8_t *out = xmalloc(usize + 1);
            if (method == 0 && csize == usize) memcpy(out, z + data, usize);
            else if (method != 8 || inflate_raw(z + data, csize, out, usize, NULL)) { free(out); return NULL; }
            *outn = usize;
            return out;
        }
        at += 46 + nl + xl + cl;
    }
    return NULL;
}

int oodle_load(int allow_download)
{
    if (decompress) return 1;
    wchar_t self[MAX_PATH];
    static const wchar_t *names[] = {L"oodle-data-shared.dll", L"oo2core_9_win64.dll", L"oo2core_8_win64.dll"};
    if (GetModuleFileNameW(sr_self, self, MAX_PATH)) {
        wchar_t *slash = wcsrchr(self, L'\\');
        if (slash) {
            slash[1] = 0;
            for (int i = 0; i < 3; i++) {
                wchar_t *p = wpath(self, names[i]);
                int ok = try_load(p);
                free(p);
                if (ok) return 1;
            }
        }
    }
    wchar_t *cached = wpath(data_dir(), names[0]);
    if (try_load(cached)) { free(cached); return 1; }
    if (!allow_download) { free(cached); return 0; }
    log_msg("downloading the Oodle decompression library (first time only)...");
    size_t zn = 0, dn = 0;
    uint8_t *zip = http_get(OODLE_HOST, OODLE_URL, &zn);
    uint8_t *dll = zip_extract(zip, zn, OODLE_ZIP_ENTRY, &dn);
    free(zip);
    if (!dll) sr_fail("the Oodle download was not in the expected format");
    wchar_t *tmp = wpath(data_dir(), L"oodle-data-shared.dll.tmp");
    HANDLE h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD put = 0;
    int ok = h != INVALID_HANDLE_VALUE && WriteFile(h, dll, (DWORD)dn, &put, NULL) && put == dn;
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    free(dll);
    if (!ok || !MoveFileExW(tmp, cached, MOVEFILE_REPLACE_EXISTING)) sr_fail("could not save the Oodle library");
    free(tmp);
    ok = try_load(cached);
    free(cached);
    if (!ok) sr_fail("the Oodle library could not be loaded");
    return 1;
}

int oodle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    if (!decompress) return -1;
    intptr_t got = decompress(in, (intptr_t)inlen, out, (intptr_t)outlen, 1, 0, 0, NULL, 0, NULL, NULL, NULL, 0, 3);
    return got == (intptr_t)outlen ? 0 : -1;
}
