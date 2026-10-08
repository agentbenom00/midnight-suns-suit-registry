// Minimal JSON parser (objects, arrays, strings with escapes, numbers, true/false/null) for suit manifests.
#include "sr.h"

typedef struct { const char *s; size_t n, at; int bad; } jp;

static void ws(jp *p)
{
    while (p->at < p->n && (p->s[p->at] == ' ' || p->s[p->at] == '\t' || p->s[p->at] == '\n' || p->s[p->at] == '\r'))
        p->at++;
}

static json *jnew(jtype t)
{
    json *j = xcalloc(1, sizeof *j);
    j->t = t;
    return j;
}

static void put_utf8(buf *b, uint32_t c)
{
    if (c < 0x80) buf_u8(b, (uint8_t)c);
    else if (c < 0x800) { buf_u8(b, 0xc0 | (c >> 6)); buf_u8(b, 0x80 | (c & 0x3f)); }
    else if (c < 0x10000) { buf_u8(b, 0xe0 | (c >> 12)); buf_u8(b, 0x80 | ((c >> 6) & 0x3f)); buf_u8(b, 0x80 | (c & 0x3f)); }
    else {
        buf_u8(b, 0xf0 | (c >> 18)); buf_u8(b, 0x80 | ((c >> 12) & 0x3f));
        buf_u8(b, 0x80 | ((c >> 6) & 0x3f)); buf_u8(b, 0x80 | (c & 0x3f));
    }
}

static int hex4(jp *p, uint32_t *v)
{
    if (p->at + 4 > p->n) return -1;
    *v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p->s[p->at++];
        *v <<= 4;
        if (c >= '0' && c <= '9') *v |= c - '0';
        else if (c >= 'a' && c <= 'f') *v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') *v |= c - 'A' + 10;
        else return -1;
    }
    return 0;
}

static char *jstring(jp *p)
{
    if (p->at >= p->n || p->s[p->at] != '"') { p->bad = 1; return NULL; }
    p->at++;
    buf b = {0};
    while (p->at < p->n && p->s[p->at] != '"') {
        char c = p->s[p->at++];
        if (c != '\\') { buf_u8(&b, (uint8_t)c); continue; }
        if (p->at >= p->n) break;
        c = p->s[p->at++];
        switch (c) {
        case 'n': buf_u8(&b, '\n'); break;
        case 't': buf_u8(&b, '\t'); break;
        case 'r': buf_u8(&b, '\r'); break;
        case 'b': buf_u8(&b, '\b'); break;
        case 'f': buf_u8(&b, '\f'); break;
        case 'u': {
            uint32_t v, lo;
            if (hex4(p, &v)) { p->bad = 1; break; }
            if (v >= 0xd800 && v < 0xdc00 && p->at + 6 <= p->n && p->s[p->at] == '\\' && p->s[p->at + 1] == 'u') {
                p->at += 2;
                if (hex4(p, &lo)) { p->bad = 1; break; }
                v = 0x10000 + ((v - 0xd800) << 10) + (lo - 0xdc00);
            }
            put_utf8(&b, v);
            break;
        }
        default: buf_u8(&b, (uint8_t)c);
        }
    }
    if (p->at >= p->n) p->bad = 1;
    p->at++;
    buf_u8(&b, 0);
    return (char *)b.p;
}

static json *value(jp *p, int depth)
{
    ws(p);
    if (p->at >= p->n || depth > 64) { p->bad = 1; return NULL; }
    char c = p->s[p->at];
    if (c == '{' || c == '[') {
        int obj = c == '{';
        json *j = jnew(obj ? J_OBJ : J_ARR);
        p->at++;
        ws(p);
        if (p->at < p->n && p->s[p->at] == (obj ? '}' : ']')) { p->at++; return j; }
        for (;;) {
            char *key = NULL;
            if (obj) {
                ws(p);
                key = jstring(p);
                ws(p);
                if (p->bad || p->at >= p->n || p->s[p->at] != ':') { free(key); p->bad = 1; return j; }
                p->at++;
            }
            json *v = value(p, depth + 1);
            j->items = xrealloc(j->items, (j->n + 1) * sizeof *j->items);
            j->keys = xrealloc(j->keys, (j->n + 1) * sizeof *j->keys);
            j->items[j->n] = v;
            j->keys[j->n] = key;
            j->n++;
            if (p->bad) return j;
            ws(p);
            if (p->at < p->n && p->s[p->at] == ',') { p->at++; continue; }
            if (p->at < p->n && p->s[p->at] == (obj ? '}' : ']')) { p->at++; return j; }
            p->bad = 1;
            return j;
        }
    }
    if (c == '"') {
        json *j = jnew(J_STR);
        j->s = jstring(p);
        return j;
    }
    if (p->n - p->at >= 4 && !strncmp(p->s + p->at, "true", 4)) { p->at += 4; json *j = jnew(J_BOOL); j->num = 1; return j; }
    if (p->n - p->at >= 5 && !strncmp(p->s + p->at, "false", 5)) { p->at += 5; return jnew(J_BOOL); }
    if (p->n - p->at >= 4 && !strncmp(p->s + p->at, "null", 4)) { p->at += 4; return jnew(J_NULL); }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char tmp[64];
        size_t k = 0;
        while (p->at < p->n && k < 63 && strchr("+-.eE0123456789", p->s[p->at])) tmp[k++] = p->s[p->at++];
        tmp[k] = 0;
        json *j = jnew(J_NUM);
        j->num = strtod(tmp, NULL);
        return j;
    }
    p->bad = 1;
    return NULL;
}

json *json_parse(const char *s, size_t n)
{
    jp p = {s, n, 0, 0};
    if (n >= 3 && (uint8_t)s[0] == 0xef && (uint8_t)s[1] == 0xbb && (uint8_t)s[2] == 0xbf) p.at = 3;   // BOM
    json *j = value(&p, 0);
    ws(&p);
    if (p.bad || p.at != p.n) { json_free(j); return NULL; }
    return j;
}

json *json_get(json *o, const char *key)
{
    if (!o || o->t != J_OBJ) return NULL;
    for (int i = 0; i < o->n; i++)
        if (o->keys[i] && !strcmp(o->keys[i], key)) return o->items[i];
    return NULL;
}

void json_free(json *j)
{
    if (!j) return;
    for (int i = 0; i < j->n; i++) { json_free(j->items[i]); if (j->keys) free(j->keys[i]); }
    free(j->items);
    free(j->keys);
    free(j->s);
    free(j);
}
