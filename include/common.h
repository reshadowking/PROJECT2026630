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
#define BUF_MAX     65535
#define STAT_INTERVAL 1

// 以太网头
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
#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_ICMP  1

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

// 五元组标识TCP流
typedef struct {
    u_int sip;
    u_int dip;
    u_short sp;
    u_short dp;
} tcp_flow_key;

// 流量统计
typedef struct {
    u_int pkt_tcp, pkt_udp, pkt_icmp, pkt_http, pkt_total;
    u_long byte_total;
} traffic_stat;

extern traffic_stat g_stat;
extern pcap_t *g_handle;
extern pcap_dumper_t *g_dumper;
extern int g_use_ncurses;

void sig_exit(int sig);

// 新增：所有解析函数声明，消除隐式声明警告
void parse_eth(const u_char *data, int len);
void parse_ipv4(const u_char *data, int len);
void parse_tcp(const u_char *data, int len, u_int sip, u_int dip);
void parse_udp(const u_char *data, int len, u_int sip, u_int dip);
void parse_http(const u_char *payload, int len);
void parse_tls(const u_char *payload, int len);

#endif