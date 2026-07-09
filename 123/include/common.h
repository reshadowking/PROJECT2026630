#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>

typedef unsigned int u_uint;
#define MAC_LEN     6
#define IPV4_LEN    4
#define IPV6_LEN    16
#define BUF_MAX     65535
#define STAT_INTERVAL 1


// UI display filter type
typedef enum {
    UI_FILTER_ALL,
    UI_FILTER_TCP,
    UI_FILTER_UDP,
    UI_FILTER_ICMP,
    UI_FILTER_IPV4,
    UI_FILTER_IPV6
} UiFilterType;
extern UiFilterType g_ui_filter;
extern char g_filter_hint[64];


// 二层以太网头
struct eth_hdr {
    u_char dst_mac[MAC_LEN];
    u_char src_mac[MAC_LEN];
    u_short eth_type;
};
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD

// IPv4头
struct ipv4_hdr {
    u_char ihl:4, ver:4;
    u_char tos;
    u_short total_len;
    u_short id;
    u_short frag_off;
    u_char ttl;
    u_char proto;
    u_short check;
    u_int saddr;
    u_int daddr;
};

// IPv6头
struct ipv6_hdr {
    u_uint ver_tc_flow;
    u_short payload_len;
    u_char next_hdr;
    u_char hop_limit;
    u_char saddr[IPV6_LEN];
    u_char daddr[IPV6_LEN];
};
#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_ICMP  1
#define PROTO_ICMPV6 58

// TCP头
struct tcp_hdr {
    u_short sport;
    u_short dport;
    u_uint seq;
    u_uint ack;
    u_char res:4, doff:4;
    u_char flags;
    u_short win;
    u_short check;
    u_short urg;
};
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

// UDP头
struct udp_hdr {
    u_short sport;
    u_short dport;
    u_short len;
    u_short check;
};

// ICMP头
struct icmp_hdr {
    u_char type;
    u_char code;
    u_short check;
    u_short id;
    u_short seq;
};

// TCP流五元组（tcp_reassemble专用）
typedef struct {
    u_int sip;
    u_int dip;
    u_short sp;
    u_short dp;
} tcp_flow_key;

// 五元组（流量统计用）
typedef struct {
    u_int sip;
    u_int dip;
    u_short sp;
    u_short dp;
    u_char proto;
} flow5_key;

// 单条五元组流量统计条目
typedef struct {
    flow5_key key;
    u_uint pkt_cnt;
    u_long byte_cnt;
} flow_stat_entry;

// 五元组哈希表大小
#define FLOW_HASH_SIZE 256

// 全局总流量统计
typedef struct {
    u_int pkt_tcp, pkt_udp, pkt_icmp, pkt_http, pkt_http_req, pkt_http_resp, pkt_dns, pkt_total;
    u_long byte_total;
} traffic_stat;

// 底层抓包全局句柄
extern pcap_t *g_handle;
extern pcap_dumper_t *g_dumper;
extern int g_use_ncurses;
extern int use_ui;
extern volatile int capture_pause;
extern volatile int exit_flag;

// 信号函数
void sig_exit(int sig);

// 业务端口定义
#define PORT_HTTP    80
#define PORT_HTTPS   443
#define PORT_DNS     53

extern char g_capture_dev[32];
extern char g_capture_filter[256];

#endif