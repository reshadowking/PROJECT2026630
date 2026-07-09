#include "http_extract.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ── Helpers ── */

/* Find \r\n\r\n in buffer, return offset to start of body (past the double CRLF).
 * Returns -1 if not found. */
static int find_header_end(const u_char *data, int len)
{
    for (int i = 0; i < len - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n') {
            return i + 4;
        }
    }
    /* Also accept \n\n (some non-standard servers) */
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == '\n' && data[i+1] == '\n') {
            return i + 2;
        }
    }
    return -1;
}

/* Parse a single header line "Name: Value\r\n" */
static int parse_header_line(const char *line, int line_len,
                             char *name_out, int name_sz,
                             char *val_out, int val_sz)
{
    const char *colon = NULL;
    for (int i = 0; i < line_len; i++) {
        if (line[i] == ':') { colon = line + i; break; }
    }
    if (!colon) return -1;

    int name_len = colon - line;
    if (name_len >= name_sz) name_len = name_sz - 1;
    memcpy(name_out, line, name_len);
    name_out[name_len] = '\0';

    /* Skip colon and optional whitespace */
    const char *val_start = colon + 1;
    while (val_start < line + line_len && (*val_start == ' ' || *val_start == '\t'))
        val_start++;
    int val_len = (line + line_len) - val_start;
    /* Trim trailing \r */
    if (val_len > 0 && val_start[val_len-1] == '\r') val_len--;
    if (val_len >= val_sz) val_len = val_sz - 1;
    memcpy(val_out, val_start, val_len);
    val_out[val_len] = '\0';
    return 0;
}

/* Case-insensitive strncmp */
static int hdr_cmp(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

/* Case-insensitive substring search */
static const char *str_casestr(const char *haystack, const char *needle)
{
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++; n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

/* Extract Content-Length value; returns -1 if not found or chunked */
static int extract_content_length(http_message *msg)
{
    for (int i = 0; i < msg->header_count; i++) {
        if (hdr_cmp(msg->headers[i].name, "content-length")) {
            return atoi(msg->headers[i].value);
        }
    }
    return -1;
}

/* Check for chunked transfer encoding */
static int is_chunked(http_message *msg)
{
    for (int i = 0; i < msg->header_count; i++) {
        if (hdr_cmp(msg->headers[i].name, "transfer-encoding")) {
            if (str_casestr(msg->headers[i].value, "chunked"))
                return 1;
        }
    }
    return 0;
}

/* ── Public API ── */

void http_msg_init(http_message *msg)
{
    memset(msg, 0, sizeof(*msg));
    msg->content_length = -1;
    msg->chunk_remaining = 0;
}

int http_is_request(const u_char *data, int len)
{
    if (len < 4) return 0;
    /* HTTP methods: GET, POST, PUT, HEAD, DELETE, PATCH, OPTIONS, CONNECT, TRACE */
    static const char *methods[] = {
        "GET ", "POST", "PUT ", "HEAD", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"
    };
    for (int i = 0; i < 9; i++) {
        int mlen = strlen(methods[i]);
        if (len >= mlen && !strncmp((const char *)data, methods[i], mlen))
            return 1;
    }
    return 0;
}

int http_is_response(const u_char *data, int len)
{
    return (len >= 7 && !strncmp((const char *)data, "HTTP/1.", 7));
}

int http_parse_headers(http_message *msg, const u_char *data, int len)
{
    /* Find end-of-headers marker */
    int body_start = find_header_end(data, len);
    if (body_start < 0) {
        /* Headers incomplete if we have < HTTP_HEADER_MAX bytes */
        if (len >= HTTP_HEADER_MAX) return -1; /* too large, error */
        return 0; /* need more data */
    }

    int header_block_len = body_start;
    if (header_block_len <= 0) return -1;

    /* Parse first line */
    const u_char *end = data + header_block_len;
    const u_char *ptr = data;

    /* Find end of first line */
    const u_char *line_end = NULL;
    for (const u_char *p = ptr; p < end - 1; p++) {
        if (*p == '\r' && *(p+1) == '\n') { line_end = p; break; }
        if (*p == '\n') { line_end = p; break; }
    }
    if (!line_end || line_end >= end) return -1;

    int first_line_len = line_end - ptr;

    /* Determine request vs response */
    if (http_is_request(ptr, first_line_len)) {
        msg->type = HTTP_MSG_REQUEST;
        /* Parse: METHOD URI HTTP/VERSION */
        char fline[2048];
        int fl = first_line_len < 2047 ? first_line_len : 2047;
        memcpy(fline, ptr, fl);
        fline[fl] = '\0';

        char *sp1 = strchr(fline, ' ');
        if (!sp1) return -1;
        *sp1 = '\0';
        strncpy(msg->method, fline, HTTP_METHOD_MAX - 1);
        msg->method[HTTP_METHOD_MAX - 1] = '\0';

        char *uri_start = sp1 + 1;
        char *sp2 = strchr(uri_start, ' ');
        if (sp2) {
            *sp2 = '\0';
            strncpy(msg->uri, uri_start, HTTP_URI_MAX - 1);
            msg->uri[HTTP_URI_MAX - 1] = '\0';
            strncpy(msg->version, sp2 + 1, HTTP_VERSION_MAX - 1);
            msg->version[HTTP_VERSION_MAX - 1] = '\0';
        } else {
            strncpy(msg->uri, uri_start, HTTP_URI_MAX - 1);
            msg->uri[HTTP_URI_MAX - 1] = '\0';
        }
    } else if (http_is_response(ptr, first_line_len)) {
        msg->type = HTTP_MSG_RESPONSE;
        /* Parse: HTTP/VERSION STATUS_CODE REASON */
        char fline[2048];
        int fl = first_line_len < 2047 ? first_line_len : 2047;
        memcpy(fline, ptr, fl);
        fline[fl] = '\0';

        char *sp1 = strchr(fline, ' ');
        if (!sp1) return -1;
        *sp1 = '\0';
        strncpy(msg->version, fline, HTTP_VERSION_MAX - 1);

        char *code_start = sp1 + 1;
        char *sp2 = strchr(code_start, ' ');
        if (sp2) {
            *sp2 = '\0';
            msg->status_code = atoi(code_start);
            strncpy(msg->reason, sp2 + 1, HTTP_REASON_MAX - 1);
            msg->reason[HTTP_REASON_MAX - 1] = '\0';
        } else {
            msg->status_code = atoi(code_start);
        }
    } else {
        return -1;
    }

    /* Advance past first line */
    ptr = line_end;
    if (*ptr == '\r') ptr++;
    ptr++; /* skip \n */

    /* Parse header lines */
    while (ptr < end) {
        /* Find next \r\n or \n */
        const u_char *hdr_end = NULL;
        for (const u_char *p = ptr; p < end - 1; p++) {
            if (*p == '\r' && *(p+1) == '\n') { hdr_end = p; break; }
            if (*p == '\n') { hdr_end = p; break; }
        }
        if (!hdr_end || hdr_end >= end) break;

        int hdr_line_len = hdr_end - ptr;
        if (hdr_line_len < 2) {
            /* Empty line = end of headers */
            break;
        }

        if (msg->header_count < HTTP_HDR_LINES_MAX) {
            parse_header_line((const char *)ptr, hdr_line_len,
                              msg->headers[msg->header_count].name,
                              HTTP_HDR_NAME_MAX,
                              msg->headers[msg->header_count].value,
                              HTTP_HDR_VAL_MAX);
            msg->header_count++;
        }

        ptr = hdr_end;
        if (*ptr == '\r') ptr++;
        ptr++; /* skip \n */
    }

    /* Determine body handling */
    msg->chunked = is_chunked(msg);
    if (msg->chunked) {
        msg->content_length = -1; /* unknown, chunked */
        msg->chunk_state = 0;     /* reading chunk size */
        msg->chunk_remaining = 0;
    } else {
        msg->content_length = extract_content_length(msg);
        if (msg->content_length < 0) {
            /* No Content-Length and not chunked: no body (or Connection: close body) */
            /* For Connection: close we set content_length to INT_MAX */
            int is_close = 0;
            for (int i = 0; i < msg->header_count; i++) {
                if (hdr_cmp(msg->headers[i].name, "connection") &&
                    hdr_cmp(msg->headers[i].value, "close")) {
                    is_close = 1;
                    break;
                }
            }
            if (is_close) {
                /* Body until connection close — special value */
                msg->content_length = 0x7FFFFFFF;
            } else {
                msg->content_length = 0; /* no body */
            }
        }
    }

    /* Allocate body buffer */
    if (msg->content_length > 0 && msg->content_length < HTTP_BODY_MAX) {
        msg->body = (u_char *)malloc(msg->content_length + 1);
        if (msg->body) {
            memset(msg->body, 0, msg->content_length + 1);
        }
    } else if (msg->chunked || msg->content_length == 0x7FFFFFFF) {
        /* Allocate progressively — start with 64KB */
        msg->body = (u_char *)malloc(65536);
        if (msg->body) {
            memset(msg->body, 0, 65536);
        }
    }

    return 1; /* headers complete */
}

/* ── Chunked transfer-encoding parser ── */

/* Read hex chunk size from data; returns chunk size or -1 on error */
static int parse_chunk_size(const u_char *data, int len, int *consumed)
{
    *consumed = 0;
    char hex[16];
    int hi = 0;
    while (*consumed < len && hi < 15) {
        char c = data[*consumed];
        if (c == '\r') {
            (*consumed)++;
            if (*consumed < len && data[*consumed] == '\n') (*consumed)++;
            break;
        }
        if (c == '\n') { (*consumed)++; break; }
        if (isxdigit((unsigned char)c) && hi < 15) {
            hex[hi++] = c;
        } else if (c == ';') {
            /* chunk extension — skip to end of line */
            while (*consumed < len && data[*consumed] != '\n') (*consumed)++;
            if (*consumed < len) (*consumed)++;
            break;
        }
        (*consumed)++;
    }
    hex[hi] = '\0';
    if (hi == 0) return -1;
    return (int)strtol(hex, NULL, 16);
}

int http_feed_body(http_message *msg, const u_char *data, int len)
{
    if (msg->body_complete) return 1;
    if (msg->content_length == 0) { msg->body_complete = 1; return -2; }

    if (msg->chunked) {
        /* Chunked transfer encoding */
        int offset = 0;
        while (offset < len && !msg->body_complete) {
            if (msg->chunk_state == 0) {
                /* Reading chunk size */
                int consumed = 0;
                int csize = parse_chunk_size(data + offset, len - offset, &consumed);
                if (csize < 0) return -1;
                offset += consumed;
                if (csize == 0) {
                    /* Final chunk — read trailers */
                    msg->chunk_state = 2;
                    msg->body_complete = 1;
                    break;
                }
                msg->chunk_remaining = csize;
                msg->chunk_state = 1;
            }

            if (msg->chunk_state == 1) {
                int avail = len - offset;
                int to_copy = (avail < msg->chunk_remaining) ? avail : msg->chunk_remaining;
                if (to_copy > 0) {
                    /* Realloc body if needed */
                    int new_len = msg->body_len + to_copy;
                    /* estimate cap */
                    if (!msg->body) {
                        msg->body = (u_char *)malloc(65536);
                    }
                    if (msg->body && new_len >= 65536 && (new_len % 65536) < to_copy + 64) {
                        msg->body = (u_char *)realloc(msg->body, new_len + 65536);
                    }
                    if (msg->body) {
                        memcpy(msg->body + msg->body_len, data + offset, to_copy);
                    }
                    msg->body_len += to_copy;
                    msg->chunk_remaining -= to_copy;
                    offset += to_copy;
                }

                if (msg->chunk_remaining == 0) {
                    /* Expect \r\n after chunk data */
                    if (offset < len && data[offset] == '\r') offset++;
                    if (offset < len && data[offset] == '\n') offset++;
                    msg->chunk_state = 0; /* back to reading next chunk size */
                }
            }
        }
        return msg->body_complete ? 1 : 0;
    }

    /* Non-chunked: just accumulate body */
    if (msg->content_length == 0x7FFFFFFF) {
        /* Connection: close — accumulate everything */
        if (!msg->body) {
            msg->body = (u_char *)malloc(65536);
        }
        int new_len = msg->body_len + len;
        if (msg->body && new_len < HTTP_BODY_MAX) {
            msg->body = (u_char *)realloc(msg->body, new_len + 1);
            if (msg->body) {
                memcpy(msg->body + msg->body_len, data, len);
                msg->body_len += len;
                msg->body[msg->body_len] = '\0';
            }
        }
        return 0; /* never complete until FIN */
    }

    /* Fixed Content-Length */
    int needed = msg->content_length - msg->body_len;
    int to_copy = (len < needed) ? len : needed;
    if (msg->body && to_copy > 0) {
        memcpy(msg->body + msg->body_len, data, to_copy);
    }
    msg->body_len += to_copy;

    if (msg->body_len >= msg->content_length) {
        msg->body_complete = 1;
        if (msg->body) msg->body[msg->body_len] = '\0';
        return 1;
    }
    return 0;
}

int http_msg_total_len(const http_message *msg)
{
    /* Approximate: headers + body */
    /* We don't store exact header length, so just return body_len as estimate */
    return msg->body_len;
}

void http_msg_free(http_message *msg)
{
    if (msg->body) {
        free(msg->body);
        msg->body = NULL;
    }
    msg->body_len = 0;
}

u_char *http_msg_serialize(const http_message *msg, int *out_len)
{
    /* Build serialized message: first line + headers + body */
    int est_size = 4096 + msg->body_len;
    u_char *buf = (u_char *)malloc(est_size + 1);
    if (!buf) return NULL;
    memset(buf, 0, est_size + 1);

    int off = 0;

    /* First line */
    if (msg->type == HTTP_MSG_REQUEST) {
        off += snprintf((char *)buf + off, est_size - off,
                        "%s %s %s\r\n",
                        msg->method, msg->uri, msg->version[0] ? msg->version : "HTTP/1.1");
    } else {
        off += snprintf((char *)buf + off, est_size - off,
                        "%s %d %s\r\n",
                        msg->version[0] ? msg->version : "HTTP/1.1",
                        msg->status_code, msg->reason);
    }

    /* Headers */
    for (int i = 0; i < msg->header_count; i++) {
        off += snprintf((char *)buf + off, est_size - off, "%s: %s\r\n",
                        msg->headers[i].name, msg->headers[i].value);
    }
    off += snprintf((char *)buf + off, est_size - off, "\r\n");

    /* Body */
    if (msg->body && msg->body_len > 0) {
        memcpy(buf + off, msg->body, msg->body_len);
        off += msg->body_len;
    }
    buf[off] = '\0';
    *out_len = off;
    return buf;
}
