#include "common.h"
#include <pthread.h>
static pthread_t stat_tid;
static int stat_running = 1;

void print_stat() {
    printf("===== Traffic Stat =====\n");
    printf("TCP:%d UDP:%d ICMP:%d HTTP:%d TotalPkt:%d TotalByte:%lu\n",
           g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp, g_stat.pkt_http,
           g_stat.pkt_total, g_stat.byte_total);
    printf("========================\n");
}

void *stat_loop(void *arg) {
    (void)arg;
    while(stat_running) {
        sleep(STAT_INTERVAL);
        print_stat();
    }
    return NULL;
}

void stat_thread_start() {
    stat_running = 1;
    pthread_create(&stat_tid, NULL, stat_loop, NULL);
}

// 新增：停止统计线程
void stat_thread_stop() {
    stat_running = 0;
    pthread_join(stat_tid, NULL);
}