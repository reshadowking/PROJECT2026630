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
#include "logger.h"

typedef unsigned int u_uint;
#define MAC_LEN     6
#define IPV4_LEN    4
#define IPV6_LEN    16
#define BUF_MAX     65535
#define STAT_INTERVAL 1

#define PARSER_WORKERS      2
#define PKT_QUEUE_SIZE      131072
#define PKT_BUF_SZ          2048
#define PCAP_BUF_MB         512
#define CAPTURE_BATCH       1024
#define KERNEL_BUF_MB       256
#define PCAP_TIMEOUT_MS     1
#define LOG_BUF_SZ          4096
#define UI_RING_SIZE        1024

/* ── TCP flow dynamic buffer limits ── */
#define FLOW_BUF_INIT       8192        /* initial buffer size */
#define FLOW_BUF_MAX        (2 * 1024 * 1024)  /* 2 MB upper limit */

typedef struct {
    struct pcap_pkthdr hdr;
    u_char data[BUF_MAX];
    int valid;
} pkt_entry_raw;

typedef struct {
    struct pcap_pkthdr hdr;
    u_char data[PKT_BUF_SZ];
    int data_len;
} pkt_entry;

typedef struct {
    struct pcap_pkthdr hdr;
    u_char data[PKT_BUF_SZ];
    int data_len;
    int valid;
} ui_ring_entry;

typedef struct {
    ui_ring_entry *entries;
    int capacity;
    volatile int head;
    volatile int tail;
    volatile int count;
    pthread_mutex_t mutex;
} ui_ring;

typedef struct {
    pkt_entry *entries;
    int capacity;
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
    volatile int shutdown;
} pkt_queue;

/* ── UI runtime display filter enum ── */
typedef enum {
    UI_FILTER_ALL,
    UI_FILTER_TCP,
    UI_FILTER_UDP,
    UI_FILTER_ICMP,
    UI_FILTER_IPV4,
    UI_FILTER_IPV6
} UiFilterType;

/* ── UI tab pages ── */
typedef enum {
    UI_TAB_PACKET_LIST,   /* 报文列表 + 协议树细节 */
    UI_TAB_TRAFFIC_STATS, /* 实时流量统计面板 */
    UI_TAB_APP_LAYER      /* 应用层信息 (HTTP/DNS/TLS) */
} UiTab;

extern UiFilterType g_ui_filter;
extern UiTab g_ui_tab;
extern char g_filter_hint[64];

/* ── Layer-2 Ethernet header ── */
struct eth_hdr {
    u_char dst_mac[MAC_LEN];
    u_char src_mac[MAC_LEN];
    u_short eth_type;
} __attribute__((packed));
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD

/* ── IPv4 header ── */
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
} __attribute__((packed));

/* ── IPv6 header ── */
struct ipv6_hdr {
    u_uint ver_tc_flow;
    u_short payload_len;
    u_char next_hdr;
    u_char hop_limit;
    u_char saddr[IPV6_LEN];
    u_char daddr[IPV6_LEN];
} __attribute__((packed));
#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_ICMP  1
#define PROTO_ICMPV6 58

/* ── TCP header ── */
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
} __attribute__((packed));
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

/* ── UDP header ── */
struct udp_hdr {
    u_short sport;
    u_short dport;
    u_short len;
    u_short check;
} __attribute__((packed));

/* ── ICMP header ── */
struct icmp_hdr {
    u_char type;
    u_char code;
    u_short check;
    u_short id;
    u_short seq;
} __attribute__((packed));

/*
 * tcp_flow_key — TCP flow 5-tuple (for tcp_reassemble).
 *
 * Supports both IPv4 and IPv6:
 *   - is_ipv6 == 0  →  use sip / dip (32-bit IPv4)
 *   - is_ipv6 == 1  →  use sip6 / dip6 (128-bit IPv6)
 * The `sip`/`dip` fields hold a 32-bit hash of the IPv6 address
 * when is_ipv6==1, so the existing hash-slot selection still works.
 */
typedef struct {
    int      is_ipv6;
    u_int    sip;                  /* IPv4 source, or hash of IPv6 low 32 bits */
    u_int    dip;                  /* IPv4 dest,   or hash of IPv6 low 32 bits */
    u_char   sip6[IPV6_LEN];      /* full IPv6 source (valid when is_ipv6==1) */
    u_char   dip6[IPV6_LEN];      /* full IPv6 dest   (valid when is_ipv6==1) */
    u_short  sp;
    u_short  dp;
} tcp_flow_key;

/*
 * flow5_key — 5-tuple for per-flow traffic statistics.
 * Same IPv4/IPv6 dual-mode strategy as tcp_flow_key.
 */
typedef struct {
    int      is_ipv6;
    u_int    sip;                  /* IPv4 source, or hash of IPv6 low 32 bits */
    u_int    dip;                  /* IPv4 dest,   or hash of IPv6 low 32 bits */
    u_char   sip6[IPV6_LEN];      /* full IPv6 source (valid when is_ipv6==1) */
    u_char   dip6[IPV6_LEN];      /* full IPv6 dest   (valid when is_ipv6==1) */
    u_short  sp;
    u_short  dp;
    u_char   proto;
} flow5_key;

/* ── Per-flow traffic statistics entry ── */
typedef struct flow_stat_entry_s {
    flow5_key key;
    u_uint pkt_cnt;
    u_long byte_cnt;
    struct flow_stat_entry_s *next;
} flow_stat_entry;

/* ── Flow hash table size ── */
#define FLOW_HASH_SIZE 256

/* ── Global aggregate traffic statistics ── */
typedef struct {
    unsigned int pkt_tcp;
    unsigned int pkt_udp;
    unsigned int pkt_icmp;
    unsigned int pkt_http;
    unsigned int pkt_dns;
    unsigned int pkt_total;
    unsigned long byte_total;
} traffic_stat;

/* ── Global capture handles ── */
extern pcap_t *g_handle;
extern pcap_dumper_t *g_dumper;
extern int g_use_ncurses;
extern int use_ui;
extern volatile int capture_pause;
extern volatile int exit_flag;

/* ── Signal handler ── */
void sig_exit(int sig);

/* ── Well-known ports ── */
#define PORT_HTTP    80
#define PORT_HTTPS   443
#define PORT_DNS     53
extern char g_capture_dev[32];
extern char g_capture_filter[256];
extern ui_ring g_ui_ring;
#endif
