#ifndef TRAFFIC_STAT_H
#define TRAFFIC_STAT_H
#include "common.h"
// 唯一全局统计变量声明
extern traffic_stat g_stat;
// 统计互斥锁 (flow_hash still needs mutex for complex ops)
extern pthread_mutex_t flow_hash_mutex;

// 封装统计递增接口（原子操作，无需mutex）
void stat_inc_http_reassemble();
void stat_inc_total(int byte);
void stat_inc_tcp();
void stat_inc_udp();
void stat_inc_icmp();
void stat_inc_http();
void stat_inc_dns();
void stat_inc_http_req();
void stat_inc_http_resp();

// 五元组流量哈希接口
void flow_stat_add(const flow5_key *key, int pkt_len);
void print_all_flow_stat();

// 安全读取统计快照
void stat_snapshot(traffic_stat *out);

void stat_thread_start();
void stat_thread_stop();
void print_stat();

/* Exposed for UI traffic tab — defined in traffic_stat.c */
extern flow_stat_entry flow_hash[FLOW_HASH_SIZE];

/* Global loss-rate counters from pcap_stats (atomic, written by capture thread) */
extern volatile u_long g_pcap_recv;
extern volatile u_long g_pcap_drop;
extern volatile u_long g_pcap_ifdrop;

#endif