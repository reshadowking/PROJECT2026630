/*
 * http_parser.c — HTTP/1.x 协议解析器实现
 *
 * 功能:
 *   1. 请求行/状态行解析 (METHOD URI HTTP/version, HTTP/version STATUS PHRASE)
 *   2. 头部键值对提取 (零拷贝, 大小写不敏感匹配)
 *   3. 分块传输编码 (chunked) 自动解码
 *   4. Content-Length / Connection: close 边界检测
 *
 * 设计:
 *   - 零拷贝: method_str, uri, version, headers 均指向原始缓冲区
 *   - 调用者通过 http_message_free() 释放整个消息树
 */

#include "http_parser.h"
#include <ctype.h>
#include <errno.h>

/* ──────────────────────────────────────────────
 *  internal helpers
 * ────────────────────────────────────────────── */

#define HEADER_INIT_CAP   16
#define BODY_INIT_CAP     4096

static const char *g_method_names[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "PATCH", "OPTIONS", "CONNECT", "TRACE", "?"
};

/* case-insensitive strncmp */
static int strnieq(const char *a, const char *b, int n)
{
    for (int i = 0; i < n; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

/* case-insensitive strstr limited to haystack_len */
static char *stristr_len(const char *haystack, int haystack_len, const char *needle)
{
    int needle_len = (int)strlen(needle);
    if (needle_len == 0 || needle_len > haystack_len) return NULL;
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        if (strnieq(haystack + i, needle, needle_len))
            return (char *)(haystack + i);
    }
    return NULL;
}

/* find \r\n or \n line ending; return pointer past it, update *line_len */
static char *next_line(char *p, char *end, int *line_len)
{
    *line_len = 0;
    if (p >= end) return NULL;
    char *cr = NULL;
    for (char *s = p; s < end; s++) {
        if (*s == '\r' && s + 1 < end && *(s + 1) == '\n') {
            cr = s;
            break;
        }
        if (*s == '\n') {
            *line_len = (int)(s - p);
            return s + 1;
        }
    }
    if (cr) {
        *line_len = (int)(cr - p);
        return cr + 2;
    }
    return NULL;
}

/* copy up to max-1 chars from src (len bytes) into dst, null-terminate */
static void safe_strcpy(char *dst, int max, const char *src, int len)
{
    if (len >= max) len = max - 1;
    memcpy(dst, src, (size_t)len);
    dst[len] = '\0';
}

/* ──────────────────────────────────────────────
 *  method helpers
 * ────────────────────────────────────────────── */

http_method_t http_method_from_str(const char *s, int len)
{
    if (!s || len <= 0) return HTTP_UNKNOWN;
    /* switch on first char for fast dispatch */
    switch (s[0]) {
    case 'G': if (len == 3 && !memcmp(s, "GET", 3))     return HTTP_GET;     break;
    case 'P':
        if (len == 4 && !memcmp(s, "POST", 4))           return HTTP_POST;
        if (len == 3 && !memcmp(s, "PUT", 3))            return HTTP_PUT;
        if (len == 5 && !memcmp(s, "PATCH", 5))          return HTTP_PATCH;
        break;
    case 'D': if (len == 6 && !memcmp(s, "DELETE", 6))   return HTTP_DELETE;  break;
    case 'H': if (len == 4 && !memcmp(s, "HEAD", 4))     return HTTP_HEAD;    break;
    case 'O': if (len == 7 && !memcmp(s, "OPTIONS", 7))  return HTTP_OPTIONS; break;
    case 'C': if (len == 7 && !memcmp(s, "CONNECT", 7))  return HTTP_CONNECT; break;
    case 'T': if (len == 5 && !memcmp(s, "TRACE", 5))    return HTTP_TRACE;   break;
    }
    return HTTP_UNKNOWN;
}

const char *http_method_name(http_method_t m)
{
    if (m >= 0 && m <= 9) return g_method_names[m];
    return "?";
}

/* ──────────────────────────────────────────────
 *  header value lookup (case-insensitive)
 * ────────────────────────────────────────────── */

static http_header_t *header_find(http_header_t *hdrs, int count,
                                  const char *name)
{
    for (int i = 0; i < count; i++) {
        if (strnieq(hdrs[i].name, name, hdrs[i].name_len) &&
            (int)strlen(name) == hdrs[i].name_len)
            return &hdrs[i];
    }
    return NULL;
}

/* ──────────────────────────────────────────────
 *  detection helpers (exported for tcp_reassemble)
 * ────────────────────────────────────────────── */

int http_detect_content_length(const char *header_start, int header_len,
                               int *out_cl)
{
    char *pos = stristr_len(header_start, header_len, "content-length:");
    if (!pos) return 0;
    pos += 15; /* skip "content-length:" */
    /* skip optional whitespace */
    while (pos < header_start + header_len && (*pos == ' ' || *pos == '\t'))
        pos++;
    if (pos >= header_start + header_len) return 0;
    char *endp = NULL;
    long val = strtol(pos, &endp, 10);
    if (endp == pos || val < 0 || val > 0x7FFFFFFF) return 0;
    *out_cl = (int)val;
    return 1;
}

int http_detect_chunked(const char *header_start, int header_len)
{
    char *pos = stristr_len(header_start, header_len, "transfer-encoding:");
    if (!pos) return 0;
    pos += 18;
    /* look for "chunked" within this header value (until end of line or headers) */
    const char *end = header_start + header_len;
    while (pos < end && *pos != '\r' && *pos != '\n') {
        if (strnieq(pos, "chunked", 7)) return 1;
        pos++;
    }
    return 0;
}

int http_detect_connection_close(const char *header_start, int header_len)
{
    char *pos = stristr_len(header_start, header_len, "connection:");
    if (!pos) return 0;
    pos += 11;
    const char *end = header_start + header_len;
    while (pos < end && *pos != '\r' && *pos != '\n') {
        if (strnieq(pos, "close", 5)) return 1;
        pos++;
    }
    return 0;
}

/* ──────────────────────────────────────────────
 *  chunked body scanner (exported)
 * ────────────────────────────────────────────── */

int http_chunked_body_complete(const u_char *body_start, int body_len,
                               int *out_decoded_len, int *out_raw_len)
{
    *out_decoded_len = 0;
    *out_raw_len = 0;
    if (!body_start || body_len <= 0) return 0;

    const char *p   = (const char *)body_start;
    const char *end = p + body_len;
    int decoded     = 0;
    int consumed    = 0;

    while (p < end) {
        /* parse chunk size hex line */
        const char *crlf = NULL;
        for (const char *s = p; s < end; s++) {
            if (*s == '\r' && s + 1 < end && *(s + 1) == '\n') {
                crlf = s; break;
            }
            if (*s == '\n') { crlf = s; break; }
        }
        if (!crlf) return 0; /* incomplete size line */

        /* parse hex size */
        int chunk_sz = 0;
        const char *hex = p;
        while (hex < crlf) {
            char c = *hex;
            int digit;
            if (c >= '0' && c <= '9')       digit = c - '0';
            else if (c >= 'a' && c <= 'f')  digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')  digit = c - 'A' + 10;
            else break; /* chunk extension or garbage — stop parsing size */
            if (chunk_sz > (0x7FFFFFFF - digit) / 16)
                return -1; /* overflow */
            chunk_sz = chunk_sz * 16 + digit;
            hex++;
        }
        if (chunk_sz < 0) return -1;

        /* advance past the size line */
        int line_adv = (*crlf == '\r') ? 2 : 1;
        p = crlf + line_adv;

        if (chunk_sz == 0) {
            /* zero-size chunk = end. Consume optional trailer lines + final CRLF. */
            while (p < end) {
                if (*p == '\r' && p + 1 < end && *(p + 1) == '\n') {
                    p += 2; break;
                }
                if (*p == '\n') { p += 1; break; }
                /* skip trailer header line */
                const char *nl = NULL;
                for (const char *s = p; s < end; s++) {
                    if (*s == '\r' && s + 1 < end && *(s + 1) == '\n') { nl = s; break; }
                    if (*s == '\n') { nl = s; break; }
                }
                if (!nl) return 0; /* incomplete trailer line */
                int adv = (*nl == '\r') ? 2 : 1;
                p = nl + adv;
            }
            consumed = (int)(p - (const char *)body_start);
            *out_decoded_len = decoded;
            *out_raw_len     = consumed;
            return 1;
        }

        /* chunk data must be chunk_sz + CRLF */
        if (p + chunk_sz + 2 > end) return 0; /* need more data */
        decoded  += chunk_sz;
        p        += chunk_sz;
        /* skip trailing CRLF after chunk data */
        if (*p == '\r' && p + 1 < end && *(p + 1) == '\n') p += 2;
        else if (*p == '\n') p += 1;
        else return -1; /* malformed */
    }
    /* ran out of data without hitting zero-chunk */
    return 0;
}

/* ──────────────────────────────────────────────
 *  message parse — core
 * ────────────────────────────────────────────── */

http_message_t *http_message_parse(const u_char *data, int len)
{
    if (!data || len < 8) return NULL;

    char *buf     = (char *)data;
    char *end     = buf + len;
    char *cur     = buf;

    http_message_t *msg = (http_message_t *)calloc(1, sizeof(http_message_t));
    if (!msg) return NULL;
    msg->content_length = -1;

    /* ── parse start-line ── */
    int line_len = 0;
    char *next = next_line(cur, end, &line_len);
    if (!next || line_len < 4) { free(msg); return NULL; }

    if (line_len >= 5 && !memcmp(cur, "HTTP/", 5)) {
        /* ── response line: HTTP/1.x SP status SP reason ── */
        msg->type = HTTP_RESPONSE;
        char *sp1 = memchr(cur, ' ', (size_t)line_len);
        if (!sp1 || sp1 >= cur + line_len) { free(msg); return NULL; }
        msg->version     = cur;
        msg->version_len = (int)(sp1 - cur);

        char *sp2 = memchr(sp1 + 1, ' ', (size_t)(cur + line_len - sp1 - 1));
        /* status code */
        char *code_s = sp1 + 1;
        while (code_s < cur + line_len && *code_s == ' ') code_s++;
        char *code_end = sp2 ? sp2 : cur + line_len;
        msg->status_code = 0;
        for (char *d = code_s; d < code_end && d < cur + line_len; d++) {
            if (*d >= '0' && *d <= '9')
                msg->status_code = msg->status_code * 10 + (*d - '0');
            else break;
        }
        /* reason phrase */
        if (sp2 && sp2 + 1 < cur + line_len) {
            msg->status_phrase      = sp2 + 1;
            msg->status_phrase_len  = (int)(cur + line_len - sp2 - 1);
        }
    } else {
        /* ── request line: METHOD SP URI SP HTTP/version ── */
        msg->type = HTTP_REQUEST;
        char *sp1 = memchr(cur, ' ', (size_t)line_len);
        if (!sp1) { free(msg); return NULL; }
        msg->method_str  = cur;
        msg->method_len  = (int)(sp1 - cur);
        msg->method      = http_method_from_str(cur, msg->method_len);

        char *sp2 = NULL;
        for (char *s = sp1 + 1; s < cur + line_len; s++) {
            if (*s == ' ') { sp2 = s; break; }
        }
        if (!sp2) { free(msg); return NULL; }
        msg->uri     = sp1 + 1;
        msg->uri_len = (int)(sp2 - sp1 - 1);

        msg->version     = sp2 + 1;
        msg->version_len = (int)(cur + line_len - sp2 - 1);
    }

    /* ── advance past start-line ── */
    cur = next;

    /* ── allocate headers array ── */
    msg->header_capacity = HEADER_INIT_CAP;
    msg->headers = (http_header_t *)calloc((size_t)msg->header_capacity,
                                            sizeof(http_header_t));
    if (!msg->headers) { http_message_free(msg); return NULL; }

    /* ── parse headers ── */
    while (cur < end) {
        /* check for empty line = end of headers */
        if (*cur == '\r' && cur + 1 < end && *(cur + 1) == '\n') {
            cur += 2; break;
        }
        if (*cur == '\n') { cur += 1; break; }

        int hl_len = 0;
        char *nl = next_line(cur, end, &hl_len);
        if (!nl) {
            /* incomplete header line — treat as end */
            break;
        }
        if (hl_len == 0) { cur = nl; continue; } /* skip blank lines */

        /* find colon separator */
        char *colon = memchr(cur, ':', (size_t)hl_len);
        if (!colon) { cur = nl; continue; } /* malformed header, skip */

        /* expand headers array if needed */
        if (msg->header_count >= msg->header_capacity) {
            int new_cap = msg->header_capacity * 2;
            http_header_t *new_hdrs = (http_header_t *)realloc(msg->headers,
                (size_t)new_cap * sizeof(http_header_t));
            if (!new_hdrs) break; /* OOM — stop parsing headers */
            msg->headers = new_hdrs;
            msg->header_capacity = new_cap;
            /* zero the newly added slots */
            memset(&msg->headers[msg->header_count], 0,
                   (size_t)(new_cap - msg->header_count) * sizeof(http_header_t));
        }

        http_header_t *hdr = &msg->headers[msg->header_count];
        hdr->name     = cur;
        hdr->name_len = (int)(colon - cur);
        /* trim trailing whitespace from name */
        while (hdr->name_len > 0 &&
               (hdr->name[hdr->name_len - 1] == ' ' ||
                hdr->name[hdr->name_len - 1] == '\t'))
            hdr->name_len--;

        char *val     = colon + 1;
        /* skip leading whitespace in value */
        while (val < cur + hl_len && (*val == ' ' || *val == '\t')) val++;
        hdr->value     = val;
        hdr->value_len = (int)(cur + hl_len - val);
        /* trim trailing whitespace from value */
        while (hdr->value_len > 0 &&
               (hdr->value[hdr->value_len - 1] == ' ' ||
                hdr->value[hdr->value_len - 1] == '\t'))
            hdr->value_len--;

        msg->header_count++;
        cur = nl;
    }

    /* ── extract well-known header values ── */
    http_header_t *h;
    h = header_find(msg->headers, msg->header_count, "content-length");
    if (h) {
        char tmp[32];
        safe_strcpy(tmp, sizeof(tmp), h->value, h->value_len);
        msg->content_length = (int)strtol(tmp, NULL, 10);
    }
    h = header_find(msg->headers, msg->header_count, "transfer-encoding");
    if (h) {
        char tmp[64];
        safe_strcpy(tmp, sizeof(tmp), h->value, h->value_len);
        if (stristr_len(tmp, (int)strlen(tmp), "chunked"))
            msg->is_chunked = 1;
    }
    h = header_find(msg->headers, msg->header_count, "connection");
    if (h) {
        char tmp[32];
        safe_strcpy(tmp, sizeof(tmp), h->value, h->value_len);
        if (stristr_len(tmp, (int)strlen(tmp), "close"))
            msg->connection_close = 1;
    }

    /* ── parse body ── */
    int body_start = (int)(cur - buf);
    int body_avail = len - body_start;

    if (msg->is_chunked && body_avail > 0) {
        /* ── decode chunked body ── */
        msg->body_capacity = BODY_INIT_CAP;
        msg->body = (u_char *)malloc((size_t)msg->body_capacity);
        if (!msg->body) { http_message_free(msg); return NULL; }
        msg->body_len = 0;

        const char *bp = cur;
        const char *bend = end;

        while (bp < bend) {
            /* read chunk size line */
            const char *crlf = NULL;
            for (const char *s = bp; s < bend; s++) {
                if (*s == '\r' && s + 1 < bend && *(s + 1) == '\n') { crlf = s; break; }
                if (*s == '\n') { crlf = s; break; }
            }
            if (!crlf) break; /* incomplete */

            int chunk_sz_hex = 0;
            const char *hex = bp;
            while (hex < crlf) {
                char c2 = *hex;
                int d;
                if (c2 >= '0' && c2 <= '9')       d = c2 - '0';
                else if (c2 >= 'a' && c2 <= 'f')  d = c2 - 'a' + 10;
                else if (c2 >= 'A' && c2 <= 'F')  d = c2 - 'A' + 10;
                else break;
                if (chunk_sz_hex > (0x7FFFFFFF - d) / 16) break;
                chunk_sz_hex = chunk_sz_hex * 16 + d;
                hex++;
            }

            int adv = (*crlf == '\r') ? 2 : 1;
            bp = crlf + adv;

            if (chunk_sz_hex == 0) {
                /* final chunk — consume trailers */
                while (bp < bend) {
                    if (*bp == '\r' && bp + 1 < bend && *(bp + 1) == '\n') { bp += 2; break; }
                    if (*bp == '\n') { bp += 1; break; }
                    const char *nl2 = NULL;
                    for (const char *s = bp; s < bend; s++) {
                        if (*s == '\r' && s + 1 < bend && *(s + 1) == '\n') { nl2 = s; break; }
                        if (*s == '\n') { nl2 = s; break; }
                    }
                    if (!nl2) break;
                    int adv2 = (*nl2 == '\r') ? 2 : 1;
                    bp = nl2 + adv2;
                }
                break;
            }

            /* ensure buffer capacity */
            if (msg->body_len + chunk_sz_hex > msg->body_capacity) {
                int new_cap = msg->body_capacity;
                while (new_cap < msg->body_len + chunk_sz_hex)
                    new_cap *= 2;
                u_char *nb = (u_char *)realloc(msg->body, (size_t)new_cap);
                if (!nb) break;
                msg->body = nb;
                msg->body_capacity = new_cap;
            }

            if (bp + chunk_sz_hex > bend) break; /* incomplete chunk data */
            memcpy(msg->body + msg->body_len, bp, (size_t)chunk_sz_hex);
            msg->body_len += chunk_sz_hex;
            bp += chunk_sz_hex;

            /* skip trailing CRLF after chunk data */
            if (bp < bend && *bp == '\r' && bp + 1 < bend && *(bp + 1) == '\n') bp += 2;
            else if (bp < bend && *bp == '\n') bp += 1;
        }
    } else if (msg->content_length > 0 && body_avail > 0) {
        /* ── fixed-length body ── */
        int copy_len = msg->content_length;
        if (copy_len > body_avail) copy_len = body_avail;
        msg->body = (u_char *)malloc((size_t)copy_len + 1);
        if (msg->body) {
            memcpy(msg->body, cur, (size_t)copy_len);
            msg->body[copy_len] = '\0';
            msg->body_len = copy_len;
            msg->body_capacity = copy_len + 1;
        }
    } else if (body_avail > 0 && !msg->is_chunked && msg->content_length < 0) {
        /* ── no explicit body length, but data follows headers ──
         *     could be Connection: close or server-speak.
         *     capture whatever is available. ── */
        msg->body = (u_char *)malloc((size_t)body_avail + 1);
        if (msg->body) {
            memcpy(msg->body, cur, (size_t)body_avail);
            msg->body[body_avail] = '\0';
            msg->body_len = body_avail;
            msg->body_capacity = body_avail + 1;
        }
    }

    return msg;
}

/* ──────────────────────────────────────────────
 *  message free
 * ────────────────────────────────────────────── */

void http_message_free(http_message_t *msg)
{
    if (!msg) return;
    free(msg->headers);
    free(msg->body);
    /* note: method_str, uri, version, status_phrase, header name/value
     *       are zero-copy pointers into the original buffer — do NOT free. */
    memset(msg, 0, sizeof(*msg));
    free(msg);
}

/* ──────────────────────────────────────────────
 *  message print (human-readable to stdout)
 * ────────────────────────────────────────────── */

void http_message_print(const http_message_t *msg)
{
    if (!msg) return;

    printf("══════════ HTTP Message ══════════\n");

    if (msg->type == HTTP_REQUEST) {
        printf("[Request]\n");
        printf("  Method : %s (%.*s)\n",
               http_method_name(msg->method),
               msg->method_len, msg->method_str ? msg->method_str : "");
        printf("  URI    : %.*s\n", msg->uri_len, msg->uri ? msg->uri : "");
        printf("  Version: %.*s\n", msg->version_len, msg->version ? msg->version : "");
    } else {
        printf("[Response]\n");
        printf("  Version: %.*s\n", msg->version_len, msg->version ? msg->version : "");
        printf("  Status : %d %.*s\n",
               msg->status_code,
               msg->status_phrase_len,
               msg->status_phrase ? msg->status_phrase : "");
    }

    /* headers */
    if (msg->header_count > 0) {
        printf("  ── Headers (%d) ──\n", msg->header_count);
        for (int i = 0; i < msg->header_count; i++) {
            printf("    %.*s: %.*s\n",
                   msg->headers[i].name_len,  msg->headers[i].name,
                   msg->headers[i].value_len, msg->headers[i].value);
        }
    }

    /* meta */
    printf("  ── Meta ──\n");
    printf("    Content-Length : %d\n", msg->content_length);
    printf("    Chunked        : %s\n", msg->is_chunked ? "yes" : "no");
    printf("    Conn-Close     : %s\n", msg->connection_close ? "yes" : "no");

    /* body */
    if (msg->body && msg->body_len > 0) {
        printf("  ── Body (%d bytes) ──\n", msg->body_len);
        /* print up to 512 bytes */
        int show = msg->body_len < 512 ? msg->body_len : 512;
        fwrite(msg->body, 1, (size_t)show, stdout);
        if (show < msg->body_len) printf("\n  ... (truncated, %d more bytes)", msg->body_len - show);
        printf("\n");
    } else {
        printf("  Body: (empty)\n");
    }
    printf("══════════════════════════════════\n");
}

/* ──────────────────────────────────────────────
 *  message log (single-line debug summary)
 * ────────────────────────────────────────────── */

void http_message_log(const http_message_t *msg)
{
    if (!msg) return;

    char method_buf[32], uri_buf[128], status_buf[32];

    if (msg->type == HTTP_REQUEST) {
        safe_strcpy(method_buf, sizeof(method_buf),
                    msg->method_str ? msg->method_str : "?", msg->method_len);
        safe_strcpy(uri_buf, sizeof(uri_buf),
                    msg->uri ? msg->uri : "/", msg->uri_len);
        LOG_DEBUG("[HTTP-REQ] %s %s %.*s | headers=%d body=%d chunked=%d cl=%d close=%d",
                  method_buf, uri_buf,
                  msg->version_len, msg->version ? msg->version : "",
                  msg->header_count, msg->body_len,
                  msg->is_chunked, msg->content_length, msg->connection_close);
    } else {
        snprintf(status_buf, sizeof(status_buf), "%d", msg->status_code);
        LOG_DEBUG("[HTTP-RESP] %.*s %d %.*s | headers=%d body=%d chunked=%d cl=%d close=%d",
                  msg->version_len, msg->version ? msg->version : "",
                  msg->status_code,
                  msg->status_phrase_len, msg->status_phrase ? msg->status_phrase : "",
                  msg->header_count, msg->body_len,
                  msg->is_chunked, msg->content_length, msg->connection_close);
    }
}
