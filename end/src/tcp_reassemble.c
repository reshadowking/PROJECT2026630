#include "common.h"
#include "traffic_stat.h"
#define FLOW_BUF_SZ 4096
#define FLOW_MAX 64
static pthread_mutex_t flow_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    tcp_flow_key key;
    u_uint exp_seq;
    char buf[FLOW_BUF_SZ];
    int buf_len;
    time_t last_active;
} tcp_flow;
static tcp_flow flow_list[FLOW_MAX];
static int flow_cnt = 0;

static int find_flow(tcp_flow_key k, time_t now, int *out_idle) {
    *out_idle = -1;
    for(int i = 0; i < flow_cnt; i++){
        if(flow_list[i].key.sip == k.sip && flow_list[i].key.dip == k.dip
           && flow_list[i].key.sp == k.sp && flow_list[i].key.dp == k.dp)
        {
            return i;
        }
        if((now - flow_list[i].last_active) > 30 && *out_idle == -1)
            *out_idle = i;
    }
    return -1;
}

static void scan_http_buffer(tcp_flow *f) {
    char *sep = strstr(f->buf, "\r\n\r\n");
    if (!sep) return;
    int full_len = sep - f->buf + 4;
    stat_inc_http_reassemble();
    int remain = f->buf_len - full_len;
    memmove(f->buf, f->buf + full_len, remain);
    f->buf_len = remain;
    f->exp_seq += full_len;
}

void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp, u_uint seq, const u_char *pay, int len) {
    pthread_mutex_lock(&flow_mutex);
    tcp_flow_key k = {sip, dip, sp, dp};
    time_t now = time(NULL);
    int idle_idx = -1;
    int idx = find_flow(k, now, &idle_idx);
    if (idx != -1) {
        tcp_flow *f = &flow_list[idx];
        f->last_active = now;
        u_uint pkt_end_seq = seq + len;
        if (pkt_end_seq <= f->exp_seq) {
            pthread_mutex_unlock(&flow_mutex);
            return;
        }
        if (f->buf_len + len >= FLOW_BUF_SZ) {
            memset(f->buf, 0, FLOW_BUF_SZ);
            f->buf_len = 0;
            f->exp_seq = seq;
        }
        memcpy(f->buf + f->buf_len, pay, len);
        f->buf_len += len;
        if (pkt_end_seq > f->exp_seq + f->buf_len) {
            f->exp_seq = seq;
        }
        scan_http_buffer(f);
        pthread_mutex_unlock(&flow_mutex);
        return;
    }
    if (idle_idx != -1) {
        tcp_flow *f = &flow_list[idle_idx];
        memset(f->buf, 0, FLOW_BUF_SZ);
        f->buf_len = 0;
        f->key = k;
        f->exp_seq = seq;
        f->last_active = now;
        int copy_len = len < FLOW_BUF_SZ - 1 ? len : FLOW_BUF_SZ - 1;
        memcpy(f->buf, pay, copy_len);
        f->buf_len = copy_len;
        scan_http_buffer(f);
        pthread_mutex_unlock(&flow_mutex);
        return;
    }
    if (flow_cnt < FLOW_MAX) {
        int new_idx = flow_cnt++;
        tcp_flow *f = &flow_list[new_idx];
        memset(f->buf, 0, FLOW_BUF_SZ);
        f->buf_len = 0;
        f->key = k;
        f->exp_seq = seq;
        f->last_active = now;
        int copy_len = len < FLOW_BUF_SZ - 1 ? len : FLOW_BUF_SZ - 1;
        memcpy(f->buf, pay, copy_len);
        f->buf_len = copy_len;
        scan_http_buffer(f);
    }
    pthread_mutex_unlock(&flow_mutex);
}

void tcp_flow_clear_all() {
    pthread_mutex_lock(&flow_mutex);
    memset(flow_list, 0, sizeof(flow_list));
    flow_cnt = 0;
    pthread_mutex_unlock(&flow_mutex);
}

int tcp_flow_active_count() {
    pthread_mutex_lock(&flow_mutex);
    int cnt = 0;
    time_t now = time(NULL);
    for(int i = 0; i < flow_cnt; i++) {
        if ((now - flow_list[i].last_active) <= 30) {
            cnt++;
        }
    }
    pthread_mutex_unlock(&flow_mutex);
    return cnt;
}