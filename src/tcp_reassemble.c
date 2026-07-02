#include "common.h"
#define FLOW_BUF_SZ 4096
#define FLOW_MAX 64
static pthread_mutex_t flow_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    tcp_flow_key key;
    u_uint next_seq;
    char buf[FLOW_BUF_SZ];
    int buf_len;
    time_t last_active;
} tcp_flow;
static tcp_flow flow_list[FLOW_MAX];
static int flow_cnt = 0;

// 移除内部锁，锁交给上层tcp_flow_add统一管理
static int find_flow(tcp_flow_key k, time_t now, int *out_idle) {
    *out_idle = -1;
    for(int i = 0; i < flow_cnt; i++){
        if(flow_list[i].key.sip == k.sip && flow_list[i].key.dip == k.dip
           && flow_list[i].key.sp == k.sp && flow_list[i].key.dp == k.dp)
        {
            return i;
        }
        if(now - flow_list[i].last_active > 30 && *out_idle == -1)
            *out_idle = i;
    }
    return -1;
}

void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp, u_uint seq, const u_char *pay, int len) {
    pthread_mutex_lock(&flow_mutex);
    tcp_flow_key k = {sip, dip, sp, dp};
    time_t now = time(NULL);
    int idle_idx = -1;
    int idx = find_flow(k, now, &idle_idx);

    if (idx != -1) {
        tcp_flow *f = &flow_list[idx];
        if(seq == f->next_seq && f->buf_len + len < FLOW_BUF_SZ) {
            memcpy(f->buf + f->buf_len, pay, len);
            f->buf_len += len;
            f->next_seq = seq + len;
            f->last_active = now;
            if(strstr(f->buf, "\r\n\r\n")) {
                printf("[TCP Reassemble HTTP]\n%s\n", f->buf);
                f->buf_len = 0;
                memset(f->buf, 0, FLOW_BUF_SZ);
            }
        }
        pthread_mutex_unlock(&flow_mutex);
        return;
    }

    if (idle_idx != -1) {
        tcp_flow *f = &flow_list[idle_idx];
        memset(f->buf, 0, FLOW_BUF_SZ);
        f->buf_len = 0;
        f->key = k;
        f->next_seq = seq + len;
        f->last_active = now;
        memcpy(f->buf, pay, len);
        f->buf_len = len;
        pthread_mutex_unlock(&flow_mutex);
        return;
    }

    if (flow_cnt < FLOW_MAX) {
        int new_idx = flow_cnt++;
        tcp_flow *f = &flow_list[new_idx];
        memset(f->buf, 0, FLOW_BUF_SZ);
        f->buf_len = len < FLOW_BUF_SZ ? len : FLOW_BUF_SZ - 1;
        memcpy(f->buf, pay, f->buf_len);
        f->key = k;
        f->next_seq = seq + f->buf_len;
        f->last_active = now;
    }

    pthread_mutex_unlock(&flow_mutex);
}

void tcp_flow_clear_all() {
    pthread_mutex_lock(&flow_mutex);
    for(int i = 0; i < flow_cnt; i++) {
        memset(&flow_list[i], 0, sizeof(tcp_flow));
    }
    flow_cnt = 0;
    pthread_mutex_unlock(&flow_mutex);
}

int tcp_flow_active_count() {
    pthread_mutex_lock(&flow_mutex);
    int cnt = 0;
    time_t now = time(NULL);
    for(int i = 0; i < flow_cnt; i++) {
        if (now - flow_list[i].last_active <= 30) {
            cnt++;
        }
    }
    pthread_mutex_unlock(&flow_mutex);
    return cnt;
}