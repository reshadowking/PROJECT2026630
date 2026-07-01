#include "common.h"
#include "traffic_stat.h"
traffic_stat g_stat = {0};
pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flow_hash_mutex = PTHREAD_MUTEX_INITIALIZER;
// 五元组哈希存储数组
flow_stat_entry flow_hash[FLOW_HASH_SIZE] = {0};
static pthread_t stat_tid;
static int stat_running = 1;
static void *stat_loop(void *arg);

// 哈希简易取模
static unsigned int flow_hash_idx(const flow5_key *k) {
    unsigned int h = k->sip ^ k->dip ^ k->sp ^ k->dp ^ k->proto;
    return h % FLOW_HASH_SIZE;
}

// 新增/更新五元组流量
void flow_stat_add(const flow5_key *key, int pkt_len) {
    pthread_mutex_lock(&flow_hash_mutex);
    unsigned int idx = flow_hash_idx(key);
    flow_stat_entry *e = &flow_hash[idx];
    if (e->pkt_cnt == 0) {
        e->key = *key;
        e->pkt_cnt = 1;
        e->byte_cnt = pkt_len;
    } else {
        if (e->key.sip == key->sip && e->key.dip == key->dip &&
            e->key.sp == key->sp && e->key.dp == key->dp) {
            e->pkt_cnt++;
            e->byte_cnt += pkt_len;
        } else {
            e->key = *key;
            e->pkt_cnt = 1;
            e->byte_cnt = pkt_len;
        }
    }
    pthread_mutex_unlock(&flow_hash_mutex);
}

// 打印全部活跃五元组流量
void print_all_flow_stat() {
    pthread_mutex_lock(&flow_hash_mutex);
    printf("--------五元组流量明细--------\n");
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        flow_stat_entry *e = &flow_hash[i];
        if (e->pkt_cnt == 0) continue;
        printf("SIP:%u DIP:%u SP:%u DP:%u PKT:%u BYTES:%lu\n",
               e->key.sip, e->key.dip, e->key.sp, e->key.dp,
               e->pkt_cnt, e->byte_cnt);
    }
    printf("-----------------------------\n");
    pthread_mutex_unlock(&stat_mutex);
}

// 全局总统计接口
void stat_inc_total(int byte) {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_total++;
    g_stat.byte_total += byte;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_tcp() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_tcp++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_udp() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_udp++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_icmp() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_icmp++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_http() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_http++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_dns() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_dns++;
    pthread_mutex_unlock(&stat_mutex);
}

// 打印汇总统计 + 每条五元组流量
void print_stat() {
    pthread_mutex_lock(&stat_mutex);
    printf("===== 全局流量汇总 =====\n");
    printf("TCP:%d UDP:%d ICMP:%d HTTP:%d DNS:%d TotalPkt:%d TotalByte:%lu\n",
           g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp, g_stat.pkt_http, g_stat.pkt_dns,
           g_stat.pkt_total, g_stat.byte_total);
    printf("========================\n");
    pthread_mutex_unlock(&stat_mutex);
    print_all_flow_stat();
}

// 优化循环：每100ms检查退出标记，无长阻塞睡眠
void *stat_loop(void *arg) {
    (void)arg;
    int tick_cnt = 0;
    const int TICK_PER_SEC = 10;
    const int PRINT_INTERVAL = 5;
    while(stat_running) {
        usleep(100000);
        if (!stat_running) break;
        tick_cnt++;
        if (tick_cnt >= TICK_PER_SEC * PRINT_INTERVAL) {
            print_stat();
            tick_cnt = 0;
        }
    }
    return NULL;
}

void stat_thread_start() {
    stat_running = 1;
    pthread_create(&stat_tid, NULL, stat_loop, NULL);
}

// 标准join，无np扩展函数
void stat_thread_stop() {
    stat_running = 0;
    pthread_join(stat_tid, NULL);
}