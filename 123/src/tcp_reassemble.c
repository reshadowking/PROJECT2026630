#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "http_extract.h"
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Constants ── */
#define MAX_FLOWS        256       /* max concurrent TCP flows */
#define DIR_BUF_INIT     (64*1024) /* initial per-direction buffer: 64 KB */
#define DIR_BUF_MAX      (2*1024*1024) /* max per-direction buffer: 2 MB */
#define FLOW_TIMEOUT     120       /* seconds before idle flow is recycled */

/* ── Per-direction reassembly buffer ── */
typedef struct {
    u_char *buf;          /* dynamically allocated buffer */
    int     cap;          /* total capacity */
    int     len;          /* valid data length (contiguous from base_seq) */
    u_int   base_seq;     /* sequence number of buf[0] */
    u_int   next_seq;     /* next expected sequence number (base_seq + len) */
    int     fin_received; /* 1 = FIN seen */
    int     syn_received; /* 1 = SYN seen (for initial seq) */
    int     data_started; /* 1 = we've started receiving payload data */

    /* HTTP message tracking */
    http_message http_msg;
    int     http_headers_done;  /* 1 = headers parsed */
    int     http_complete;      /* 1 = request/response fully extracted */
} dir_buf;

/* ── Bidirectional TCP flow ── */
typedef struct {
    tcp_flow_key  key;          /* client→server direction key */
    tcp_flow_key  rev_key;      /* server→client direction key */
    dir_buf       c2s;          /* client→server data */
    dir_buf       s2c;          /* server→client data */
    time_t        last_active;
    int           active;
    int           http_extracted; /* count of pairs extracted from this flow */
} tcp_flow;

/* ── Global state ── */
static tcp_flow   g_flows[MAX_FLOWS];
static int        g_flow_count = 0;
static int        g_http_pairs = 0;
static pthread_mutex_t g_flow_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE      *g_log_file = NULL;
static char       g_log_path[256] = "http_pairs.log";

/* ── Forward declarations ── */
static void dir_buf_init(dir_buf *d);
static void dir_buf_free(dir_buf *d);
static int  dir_buf_append(dir_buf *d, u_int seq, const u_char *data, int len);
static void dir_buf_mark_fin(dir_buf *d);
static void try_extract_http(dir_buf *d, int is_request);
static void log_http_message(http_message *msg, const char *direction);
static int  find_or_create_flow(tcp_flow_key k, tcp_flow_key rk, time_t now);

/* ── Dir-buffer operations ── */

static void dir_buf_init(dir_buf *d)
{
    memset(d, 0, sizeof(*d));
    d->cap = DIR_BUF_INIT;
    d->buf = (u_char *)malloc(d->cap);
    if (d->buf) memset(d->buf, 0, d->cap);
    http_msg_init(&d->http_msg);
}

static void dir_buf_free(dir_buf *d)
{
    if (d->buf) { free(d->buf); d->buf = NULL; }
    http_msg_free(&d->http_msg);
    d->cap = 0;
    d->len = 0;
}

static void dir_buf_grow(dir_buf *d, int needed)
{
    int new_cap = d->cap;
    while (new_cap < needed && new_cap < DIR_BUF_MAX)
        new_cap *= 2;
    if (new_cap > DIR_BUF_MAX) new_cap = DIR_BUF_MAX;
    if (new_cap <= d->cap) return;

    u_char *new_buf = (u_char *)realloc(d->buf, new_cap);
    if (new_buf) {
        memset(new_buf + d->cap, 0, new_cap - d->cap);
        d->buf = new_buf;
        d->cap = new_cap;
    }
}

static int dir_buf_append(dir_buf *d, u_int seq, const u_char *data, int len)
{
    if (len <= 0) return 0;

    if (!d->data_started) {
        /* First data segment on this direction */
        d->base_seq = seq;
        d->next_seq = seq;
        d->len = 0;
        d->data_started = 1;
    }

    /* Compute offset within buffer */
    int offset = (int)(seq - d->base_seq);

    /* If segment is entirely before our buffer, skip (retransmission) */
    if (offset + len <= 0) return 0;

    /* If segment starts way before our buffer base, we can't handle it.
     * Adjust base_seq downward and shift buffer. */
    if (offset < 0) {
        int shift = -offset;
        int new_len = d->len + shift;
        dir_buf_grow(d, new_len + len);
        if (d->cap >= new_len + len) {
            memmove(d->buf + shift, d->buf, d->len);
            memset(d->buf, 0, shift);
            d->base_seq = seq;
            d->next_seq = d->base_seq + d->len + shift;
            d->len = new_len;
            offset = 0;
        } else {
            return -1; /* can't grow */
        }
    }

    /* Ensure buffer is large enough */
    int needed = offset + len;
    if (needed > d->cap) {
        dir_buf_grow(d, needed);
        if (needed > d->cap) {
            /* truncate */
            len = d->cap - offset;
            if (len <= 0) return -1;
        }
    }

    /* Copy data into position */
    memcpy(d->buf + offset, data, len);

    /* Update length if we extended */
    if (offset + len > d->len) {
        d->len = offset + len;
        d->next_seq = d->base_seq + d->len;
    }

    return 0;
}

static void dir_buf_consume(dir_buf *d, int bytes)
{
    if (bytes <= 0) return;
    if (bytes >= d->len) {
        d->len = 0;
        d->base_seq = d->next_seq;
    } else {
        memmove(d->buf, d->buf + bytes, d->len - bytes);
        d->len -= bytes;
        d->base_seq += bytes;
    }
}

static void dir_buf_mark_fin(dir_buf *d)
{
    d->fin_received = 1;
    /* If connection-close body, mark it complete */
    if (d->http_headers_done && !d->http_complete &&
        d->http_msg.content_length == 0x7FFFFFFF) {
        d->http_msg.body_complete = 1;
        d->http_complete = 1;
    }
}

/* ── HTTP extraction ── */

static void try_extract_http(dir_buf *d, int is_request)
{
    if (d->http_complete) return;
    if (d->len <= 0) return;

    /* Phase 1: parse headers */
    if (!d->http_headers_done) {
        /* Try to find end of headers */
        int ret = http_parse_headers(&d->http_msg, d->buf, d->len);
        if (ret == 0) {
            /* Need more data — check if buffer is too large for headers only */
            if (d->len > HTTP_HEADER_MAX) {
                /* Headers too large, give up on this message */
                d->http_complete = 1;
                return;
            }
            return; /* wait for more data */
        }
        if (ret < 0) {
            /* Parse error — discard */
            d->http_complete = 1;
            return;
        }

        /* Headers parsed! Find the header block end to determine body offset */
        const u_char *sep = NULL;
        for (int i = 0; i < d->len - 3; i++) {
            if (d->buf[i] == '\r' && d->buf[i+1] == '\n' &&
                d->buf[i+2] == '\r' && d->buf[i+3] == '\n') {
                sep = d->buf + i + 4;
                break;
            }
        }
        if (!sep) {
            for (int i = 0; i < d->len - 1; i++) {
                if (d->buf[i] == '\n' && d->buf[i+1] == '\n') {
                    sep = d->buf + i + 2;
                    break;
                }
            }
        }
        if (!sep) {
            d->http_complete = 1;
            return;
        }

        int hdr_len = sep - d->buf;
        d->http_headers_done = 1;

        /* Feed any body data that follows headers */
        int body_avail = d->len - hdr_len;
        if (body_avail > 0) {
            int br = http_feed_body(&d->http_msg, sep, body_avail);
            if (br == 1) {
                d->http_complete = 1;
            } else if (br == -2) {
                d->http_complete = 1; /* no body */
            }
        } else if (d->http_msg.content_length == 0) {
            d->http_complete = 1; /* no body */
        }
    } else {
        /* Headers done, feed remaining buffer as body */
        int br = http_feed_body(&d->http_msg, d->buf, d->len);
        if (br == 1) {
            d->http_complete = 1;
        }
    }

    /* If complete, log it */
    if (d->http_complete) {
        const char *dir = is_request ? "REQUEST" : "RESPONSE";
        log_http_message(&d->http_msg, dir);
        if (is_request)
            stat_inc_http_req();
        else
            stat_inc_http_resp();
        __atomic_add_fetch(&g_http_pairs, 1, __ATOMIC_RELAXED);

        /* Consume the message from buffer */
        int consumed = d->len; /* conservative: consume everything parsed */
        dir_buf_consume(d, consumed);

        /* Reset HTTP state for next message on this flow */
        http_msg_free(&d->http_msg);
        http_msg_init(&d->http_msg);
        d->http_headers_done = 0;
        d->http_complete = 0;

        /* Try to extract more messages from remaining buffer */
        try_extract_http(d, is_request);
    }
}

/* ── Logging ── */

static void ensure_log_open(void)
{
    if (g_log_file) return;
    g_log_file = fopen(g_log_path, "a");
    if (g_log_file) {
        time_t now = time(NULL);
        fprintf(g_log_file, "\n=== HTTP Extraction Session: %s ===\n", ctime(&now));
        fflush(g_log_file);
    }
}

static void log_http_message(http_message *msg, const char *direction)
{
    ensure_log_open();
    if (!g_log_file) return;

    fprintf(g_log_file, "\n--- %s ---\n", direction);
    if (msg->type == HTTP_MSG_REQUEST) {
        fprintf(g_log_file, "%s %s %s\n", msg->method, msg->uri, msg->version);
    } else {
        fprintf(g_log_file, "%s %d %s\n", msg->version[0] ? msg->version : "HTTP/1.1",
                msg->status_code, msg->reason);
    }

    for (int i = 0; i < msg->header_count; i++) {
        fprintf(g_log_file, "%s: %s\n", msg->headers[i].name, msg->headers[i].value);
    }
    fprintf(g_log_file, "\n");

    if (msg->body && msg->body_len > 0 && msg->body_len < 65536) {
        /* Print printable body (truncated) */
        int show = msg->body_len < 4096 ? msg->body_len : 4096;
        fprintf(g_log_file, "%.*s", show, msg->body);
        if (msg->body_len > 4096)
            fprintf(g_log_file, "\n... [truncated, total %d bytes]\n", msg->body_len);
        fprintf(g_log_file, "\n");
    } else if (msg->body && msg->body_len >= 65536) {
        fprintf(g_log_file, "[Body: %d bytes — too large to display]\n", msg->body_len);
    }

    fflush(g_log_file);
}

/* ── Flow management ── */

static int find_flow_idx(tcp_flow_key k, tcp_flow_key rk, time_t now, int *out_idle)
{
    *out_idle = -1;
    for (int i = 0; i < g_flow_count; i++) {
        if (!g_flows[i].active) continue;
        /* Check both directions */
        if ((g_flows[i].key.sip == k.sip && g_flows[i].key.dip == k.dip &&
             g_flows[i].key.sp == k.sp && g_flows[i].key.dp == k.dp) ||
            (g_flows[i].key.sip == rk.sip && g_flows[i].key.dip == rk.dip &&
             g_flows[i].key.sp == rk.sp && g_flows[i].key.dp == rk.dp)) {
            return i;
        }
        /* Check reversed keys */
        if ((g_flows[i].key.sip == k.dip && g_flows[i].key.dip == k.sip &&
             g_flows[i].key.sp == k.dp && g_flows[i].key.dp == k.sp) ||
            (g_flows[i].key.sip == rk.dip && g_flows[i].key.dip == rk.sip &&
             g_flows[i].key.sp == rk.dp && g_flows[i].key.dp == rk.sp)) {
            return i;
        }
        /* Find idle slot */
        if (*out_idle < 0 && (now - g_flows[i].last_active) > FLOW_TIMEOUT) {
            *out_idle = i;
        }
    }
    return -1;
}

static void init_flow(tcp_flow *f, tcp_flow_key k, tcp_flow_key rk, time_t now)
{
    memset(f, 0, sizeof(*f));
    f->key = k;
    f->rev_key = rk;
    f->last_active = now;
    f->active = 1;
    dir_buf_init(&f->c2s);
    dir_buf_init(&f->s2c);
}

static void reset_flow(tcp_flow *f, tcp_flow_key k, tcp_flow_key rk, time_t now)
{
    dir_buf_free(&f->c2s);
    dir_buf_free(&f->s2c);
    init_flow(f, k, rk, now);
}

static int find_or_create_flow(tcp_flow_key k, tcp_flow_key rk, time_t now)
{
    int idle_idx;
    int idx = find_flow_idx(k, rk, now, &idle_idx);
    if (idx >= 0) return idx;

    if (idle_idx >= 0) {
        reset_flow(&g_flows[idle_idx], k, rk, now);
        return idle_idx;
    }

    if (g_flow_count < MAX_FLOWS) {
        int ni = g_flow_count++;
        init_flow(&g_flows[ni], k, rk, now);
        return ni;
    }

    return -1; /* no space */
}

/* ── Public API ── */

void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp,
                  u_uint seq, u_char flags, const u_char *pay, int len)
{
    if (len <= 0 && !(flags & (TCP_FIN | TCP_RST))) return;

    pthread_mutex_lock(&g_flow_mutex);
    time_t now = time(NULL);

    /* Build keys for both directions */
    tcp_flow_key c2s = {sip, dip, sp, dp};
    tcp_flow_key s2c = {dip, sip, dp, sp};

    int idx = find_or_create_flow(c2s, s2c, now);
    if (idx < 0) {
        pthread_mutex_unlock(&g_flow_mutex);
        return;
    }

    tcp_flow *f = &g_flows[idx];
    f->last_active = now;

    /* Determine direction */
    int is_c2s = (f->key.sip == sip && f->key.dip == dip &&
                  f->key.sp == sp && f->key.dp == dp);
    dir_buf *dir = is_c2s ? &f->c2s : &f->s2c;
    int is_request = is_c2s; /* client→server = HTTP request by default */

    /* Track SYN for initial sequence number */
    if (flags & TCP_SYN) {
        dir->syn_received = 1;
        /* SYN consumes one sequence number */
        if (len > 0) {
            /* SYN with data (unusual but possible) — skip the SYN byte */
            if (len > 1) {
                dir_buf_append(dir, seq + 1, pay + 1, len - 1);
            }
        }
    } else if (flags & TCP_RST) {
        /* RST — if we have pending HTTP data, try to finalize */
        if (dir->http_headers_done && !dir->http_complete) {
            dir->http_msg.body_complete = 1;
            dir->http_complete = 1;
            const char *dlabel = is_request ? "REQUEST" : "RESPONSE";
            log_http_message(&dir->http_msg, dlabel);
            if (is_request) stat_inc_http_req();
            else stat_inc_http_resp();
            __atomic_add_fetch(&g_http_pairs, 1, __ATOMIC_RELAXED);
        }
        /* Mark flow for cleanup */
        f->active = 0;
        pthread_mutex_unlock(&g_flow_mutex);
        return;
    } else if (len > 0) {
        dir_buf_append(dir, seq, pay, len);
    }

    if (flags & TCP_FIN) {
        dir_buf_mark_fin(dir);
        /* Try to finalize pending HTTP message */
        if (dir->http_headers_done && !dir->http_complete) {
            dir->http_msg.body_complete = 1;
            dir->http_complete = 1;
            const char *dlabel = is_request ? "REQUEST" : "RESPONSE";
            log_http_message(&dir->http_msg, dlabel);
            if (is_request) stat_inc_http_req();
            else stat_inc_http_resp();
            __atomic_add_fetch(&g_http_pairs, 1, __ATOMIC_RELAXED);
        }
    }

    /* Try HTTP extraction */
    if (dir->len > 0) {
        try_extract_http(dir, is_request);
    }

    pthread_mutex_unlock(&g_flow_mutex);
}

int tcp_flow_active_count(void)
{
    pthread_mutex_lock(&g_flow_mutex);
    int cnt = 0;
    time_t now = time(NULL);
    for (int i = 0; i < g_flow_count; i++) {
        if (g_flows[i].active && (now - g_flows[i].last_active) <= FLOW_TIMEOUT) {
            cnt++;
        }
    }
    pthread_mutex_unlock(&g_flow_mutex);
    return cnt;
}

int tcp_flow_http_pairs(void)
{
    return __atomic_load_n(&g_http_pairs, __ATOMIC_RELAXED);
}

const char *tcp_flow_log_path(void)
{
    return g_log_path;
}

void tcp_flow_clear_all(void)
{
    pthread_mutex_lock(&g_flow_mutex);
    for (int i = 0; i < g_flow_count; i++) {
        dir_buf_free(&g_flows[i].c2s);
        dir_buf_free(&g_flows[i].s2c);
    }
    memset(g_flows, 0, sizeof(g_flows));
    g_flow_count = 0;
    if (g_log_file) {
        fprintf(g_log_file, "\n=== Session End ===\n");
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_flow_mutex);
}
