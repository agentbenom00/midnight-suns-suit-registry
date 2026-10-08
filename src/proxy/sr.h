// Midnight Suns suit registry, all inside version.dll. Shared declarations.
#pragma once
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REG_PAK L"zz_MidnightSuns_SuitRegistry_P.pak"
#define STATE_PATH "CodaGame/SuitRegistry/state.json"
#define DATA_DIR_NAME L"MidnightSunsSuitRegistry"

// ---- errors: sr_fail() jumps back to the innermost sr_try
extern jmp_buf *sr_jmp;
extern char sr_error[1024];
__attribute__((noreturn)) void sr_fail(const char *fmt, ...);

// ---- memory / growable buffer
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

typedef struct { uint8_t *p; size_t n, cap; } buf;
void buf_reserve(buf *b, size_t extra);
void buf_put(buf *b, const void *d, size_t n);
void buf_u8(buf *b, uint8_t v);
void buf_u16be(buf *b, uint16_t v);
void buf_u32(buf *b, uint32_t v);
void buf_u64(buf *b, uint64_t v);
void buf_fstring(buf *b, const char *s);                    // int32 length (with the 0) + ASCII + 0
void buf_free(buf *b);

static inline uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static inline uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

// bounds-checked little-endian reader over a byte array
typedef struct { const uint8_t *p; size_t n, at; } rd;
void rd_need(rd *r, size_t n);
uint8_t rd_u8(rd *r);
uint32_t rd_u32(rd *r);
int32_t rd_i32(rd *r);
uint64_t rd_u64(rd *r);
void rd_skip(rd *r, size_t n);
char *rd_fstring(rd *r);                                    // malloc'd UTF-8; UTF-16 strings are converted
void rd_skip_fstring(rd *r);

// ---- files (wide paths)
uint8_t *file_read_all(const wchar_t *path, size_t *n);    // NULL if missing/unreadable
wchar_t *wpath(const wchar_t *a, const wchar_t *b);        // a\b, malloc'd
wchar_t *utf8_to_w(const char *s);
char *w_to_utf8(const wchar_t *s);
const wchar_t *data_dir(void);                              // %LOCALAPPDATA%\MidnightSunsSuitRegistry (created)

// ---- log (file in data_dir + the console when one is open)
void log_open(void);
void log_msg(const char *fmt, ...);
void console_show(void);

// ---- hashing / crypto
uint64_t city_hash64(const uint8_t *s, size_t len);
uint64_t fnv1a64(const void *p, size_t n);
void sha1(const void *p, size_t n, uint8_t out[20]);        // bcrypt, loaded on demand
typedef struct sha1_ctx sha1_ctx;
sha1_ctx *sha1_begin(void);
void sha1_add(sha1_ctx *c, const void *p, size_t n);
void sha1_end(sha1_ctx *c, uint8_t out[20]);
int aes_available(void);                                    // only outside DllMain
void aes256_ecb_decrypt(const uint8_t key[32], uint8_t *p, size_t n);

// ---- compression
// zlib stream (header + deflate + adler) or raw deflate; 0 on success
int inflate_raw(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, size_t *consumed);
int inflate_zlib(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
size_t deflate_zlib(const uint8_t *in, size_t n, uint8_t *out, size_t outcap);   // returns size, 0 if it didn't fit
size_t deflate_bound(size_t n);
int oodle_load(int allow_download);                         // 1 if Oodle is usable
int oodle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

// ---- paks
typedef struct {
    char *path;                                             // relative to the game folder, e.g. CodaGame/AssetRegistry.bin
    int64_t offset, size, usize;
    int method;                                             // index into pak.methods (0 = none)
    int encrypted;
    uint32_t block_size;
    int nblocks;
    int64_t *blocks;                                        // start, end pairs (absolute file offsets)
} pak_entry;

typedef struct {
    HANDLE h;
    int64_t length;
    int version;
    int encrypted_index;
    char methods[6][33];
    char *mount;                                            // mount point relative to the game folder ("" or "CodaGame/")
    uint8_t *index; size_t index_n;
    int64_t fdi_offset, fdi_size;
    uint8_t *encoded; size_t encoded_n;
    uint8_t *legacy; size_t legacy_n; int legacy_count; size_t legacy_at;
} pak;

// filter: return 1 to keep (dir is relative to the game folder with a trailing '/', or "" at the root)
typedef int (*pak_filter)(const char *dir, const char *name, void *ctx);
int pak_open(pak *pk, const wchar_t *path, int allow_aes);  // 0 = ok, -1 not a pak, -2 needs AES
void pak_close(pak *pk);
pak_entry *pak_list(pak *pk, pak_filter f, void *ctx, int *count);
void pak_entries_free(pak_entry *e, int count);
uint8_t *pak_read(pak *pk, pak_entry *e, int allow_oodle);  // NULL + sr_error if it can't (e.g. Oodle not loaded)

typedef struct { const char *path; const uint8_t *data; size_t n; int compress; } pak_out_file;
typedef struct pak_writer pak_writer;
pak_writer *pak_write_begin(const wchar_t *tmp_path);       // NULL: could not create (GetLastError)
void pak_write_file(pak_writer *w, const char *path, const uint8_t *data, size_t n, int compress);
void pak_write_end(pak_writer *w);

// ---- JSON (just enough for manifests)
typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;
typedef struct json { jtype t; char *s; double num; int n; struct json **items; char **keys; } json;
json *json_parse(const char *s, size_t n);                  // NULL on error
json *json_get(json *o, const char *key);
void json_free(json *j);

// ---- asset registry
typedef struct reg reg;
reg *reg_parse(uint8_t *data, size_t n);                    // keeps data (frees it in reg_free)
void reg_free(reg *r);
typedef char *(*rename_fn)(const char *s, void *ctx);       // malloc'd new name, or NULL = unchanged
int reg_clone(reg *r, const char *object_path, rename_fn rn, void *ctx);   // 0 ok, -1 not in the registry
uint8_t *reg_build(reg *r, size_t *n);

// ---- the sync
int sync_quick_check(const wchar_t *paks);                  // in DllMain: 1 = something to do (or unsure)
int sync_run(const wchar_t *paks, int interactive);         // the full sync, in its own process
