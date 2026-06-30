#include "common.h"
#define FLOW_BUF_SZ 4096
#define FLOW_MAX 64
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
    int idle_idx = -1;
    time_t now = time(NULL);
    for(int i=0;i<flow_cnt;i++){
        // 匹配五元组
        if(flow_list[i].key.sip==k.sip && flow_list[i].key.dip==k.dip
           && flow_list[i].key.sp==k.sp && flow_list[i].key.dp==k.dp)
            return i;
        // 记录超过30秒无活动的流，可覆盖
        if(now - flow_list[i].last_active > 30)
            idle_idx = i;
    }
    // 有空位直接新增
    if(flow_cnt < FLOW_MAX)
        return flow_cnt++;
    // 无空位，复用过期流
    return idle_idx;
}

void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp, u_uint seq, u_char *pay, int len) {
    tcp_flow_key k = {sip,dip,sp,dp};
    int idx = find_flow(k);
    if(idx == -1) return; // 满且无过期流，丢弃

    tcp_flow *f = &flow_list[idx];
    // 新占用/过期复用，清空缓存
    if(f->buf_len > 0 && (f->key.sip != k.sip || f->key.dip != k.dip || f->key.sp != k.sp || f->key.dp != k.dp)){
        memset(f->buf, 0, FLOW_BUF_SZ);
        f->buf_len = 0;
        f->next_seq = seq;
    }
    f->key = k;
    f->last_active = time(NULL);

    if(seq == f->next_seq && f->buf_len + len < FLOW_BUF_SZ) {
        memcpy(f->buf + f->buf_len, pay, len);
        f->buf_len += len;
        f->next_seq = seq + len;
        // 检测HTTP完整报文输出
        if(strstr(f->buf, "\r\n\r\n")) {
            printf("[TCP Reassemble HTTP]\n%s\n", f->buf);
            f->buf_len = 0;
            memset(f->buf,0,FLOW_BUF_SZ);
        }
    }
}