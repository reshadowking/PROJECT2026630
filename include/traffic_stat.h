#ifndef TRAFFIC_STAT_H
#define TRAFFIC_STAT_H
#include "common.h"
extern traffic_stat g_stat;
extern flow_stat_entry *flow_hash[FLOW_HASH_SIZE];

void stat_inc_http_reassemble(void);
void stat_inc_total(int byte);
void stat_inc_tcp(void);
void stat_inc_udp(void);
void stat_inc_icmp(void);
void stat_inc_http(void);
void stat_inc_dns(void);

void flow_stat_add(const flow5_key *key, int pkt_len);
void print_all_flow_stat(void);

void stat_thread_start(void);
void stat_thread_stop(void);
void print_stat(void);
#endif