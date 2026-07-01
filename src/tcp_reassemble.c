#include "common.h"
#define FLOW_BUF_SZ 4096
#define FLOW_MAX 64
// 流表互斥锁，解决抓包多线程并发竞争
static pthread_mutex_t flow_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    tcp_flow_key key;
    u_uint next_seq;
    char buf[FLOW_BUF_SZ];
    int buf_len;
    time_t last_active; // 新增最后活跃时间
} tcp_flow;
static tcp_flow flow_list[FLOW_MAX];
static int flow_cnt = 0;
// 查找流；找不到返回空闲/过期下标
static int find_flow(tcp_flow_key k) {
    pthread_mutex_lock(&flow_mutex);
    int idle_idx = -1;
    time_t now = time(NULL);
    for(int i=0;i<flow_cnt;i++){
        if(flow_list[i].key.sip==k.sip && flow_list[i].key.dip==k.dip
           && flow_list[i].key.sp==k.sp && flow_list[i].key.dp==k.dp)
        {
            pthread_mutex_unlock(&flow_mutex);
            return i;
        }
        if(now - flow_list[i].last_active > 30)
            idle_idx = i;
    }
    if(flow_cnt < FLOW_MAX)
        flow_cnt++;
    pthread_mutex_unlock(&flow_mutex);
    return idle_idx;
}
// pay 形参改为 const u_char *
void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp, u_uint seq, const u_char *pay, int len) {
    pthread_mutex_lock(&flow_mutex);
    tcp_flow_key k = {sip,dip,sp,dp};
    int idx = find_flow(k);
    if(idx == -1) {
        pthread_mutex_unlock(&flow_mutex);
        return;
    }
    tcp_flow *f = &flow_list[idx];
    if(f->buf_len > 0 && (f->key.sip != k.sip || f->key.dip != k.dip || f->key.sp != k.sp || f->key.dp != k.dp)){
        memset(f->buf, 0, FLOW_BUF_SZ);
        f->buf_len = 0;
        f->next_seq = seq;
    }
    f->key = k;
    f->last_active = time(NULL);
    if(seq == f->next_seq && f->buf_len + len < FLOW_BUF_SZ) {
        memcpy(f->buf, pay, len);
        f->buf_len += len;
        f->next_seq = seq + len;
        if(strstr(f->buf, "\r\n\r\n")) {
            printf("[TCP Reassemble HTTP]\n%s\n", f->buf);
            f->buf_len = 0;
            memset(f->buf,0,FLOW_BUF_SZ);
        }
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