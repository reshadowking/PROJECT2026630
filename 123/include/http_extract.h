#ifndef HTTP_EXTRACT_H
#define HTTP_EXTRACT_H

#include "common.h"

/* Maximum sizes */
#define HTTP_HEADER_MAX    8192    /* max header block size */
#define HTTP_BODY_MAX      (4*1024*1024)  /* max body size (4 MB) */
#define HTTP_URI_MAX       2048
#define HTTP_METHOD_MAX    16
#define HTTP_VERSION_MAX   16
#define HTTP_REASON_MAX    64
#define HTTP_HDR_LINES_MAX 64
#define HTTP_HDR_NAME_MAX  64
#define HTTP_HDR_VAL_MAX   512

/* HTTP message types */
typedef enum {
    HTTP_MSG_REQUEST,
    HTTP_MSG_RESPONSE
} http_msg_type;

/* Single header line */
typedef struct {
    char name[HTTP_HDR_NAME_MAX];
    char value[HTTP_HDR_VAL_MAX];
} http_header_line;

/* Parsed HTTP message */
typedef struct {
    http_msg_type type;

    /* Request fields */
    char method[HTTP_METHOD_MAX];
    char uri[HTTP_URI_MAX];
    char version[HTTP_VERSION_MAX];

    /* Response fields */
    int  status_code;
    char reason[HTTP_REASON_MAX];

    /* Headers */
    http_header_line headers[HTTP_HDR_LINES_MAX];
    int  header_count;

    /* Content-Length from headers (0 = no body, -1 = chunked) */
    int  content_length;

    /* Body */
    u_char *body;
    int  body_len;        /* current accumulated body length */
    int  body_complete;   /* 1 when body is fully received */
    int  chunked;         /* 1 if Transfer-Encoding: chunked */

    /* Chunked state */
    int  chunk_state;     /* 0=reading-size, 1=reading-data, 2=reading-trailer */
    int  chunk_remaining; /* bytes remaining in current chunk */
} http_message;

/* ── API ── */

/* Initialise an http_message structure */
void http_msg_init(http_message *msg);

/* Feed header data. Returns:
 *   1  = headers are complete, body follows (check msg->content_length)
 *   0  = need more header data
 *  -1  = parse error */
int http_parse_headers(http_message *msg, const u_char *data, int len);

/* Feed body data. Returns:
 *   1  = body is complete
 *   0  = need more body data
 *  -1  = parse error
 *  -2  = no body expected (content_length was 0) */
int http_feed_body(http_message *msg, const u_char *data, int len);

/* Check if a raw buffer starts with an HTTP request or response line */
int http_is_request(const u_char *data, int len);
int http_is_response(const u_char *data, int len);

/* Get total message size (headers + body) once complete */
int http_msg_total_len(const http_message *msg);

/* Free internal body buffer */
void http_msg_free(http_message *msg);

/* Snapshot the complete message into a flat buffer (caller must free). */
u_char *http_msg_serialize(const http_message *msg, int *out_len);

#endif
