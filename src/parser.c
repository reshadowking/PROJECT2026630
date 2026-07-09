/*
 * parser.c — 协议解析模块
 *
 * 功能: 逐层解析以太网 / IPv4 / IPv6 / TCP / UDP / ICMP / DNS / HTTP / TLS
 *
 * 架构: 由 parser_worker 线程调用 parse_packet() 入口,
 *       沿协议栈逐层分发: ETH → IP → TCP/UDP/ICMP → HTTP/DNS/TLS
 *
 * IPv6 修复: 完整传递 128 位地址到 tcp_flow_add / flow_stat_add,
 *           不再使用 fake_ip=0, 正确区分不同 IPv6 流。
 */

#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "tls_sni.h"
#include "dns.h"

/*
 * hash_ipv6_addr — 将 128 位 IPv6 地址折半异或为 32 位哈希值
 *   用于 flow key 的 sip/dip 字段 (非加密用途, 仅用于哈希分桶)
 */
static u_int hash_ipv6_addr(const u_char *addr)
{
    u_int h = 0;
    for (int i = 0; i < IPV6_LEN; i += 4) {
        u_int w = ((u_int)addr[i] << 24) | ((u_int)addr[i+1] << 16) |
                  ((u_int)addr[i+2] << 8) | (u_int)addr[i+3];
        h ^= w;
    }
    return h;
}

/*
 * add_flow_stat — 将五元组流量统计写入全局哈希表
 *
 * IPv4 路径: is_ipv6=0, 使用 sip/dip (不含 sip6/dip6)
 * IPv6 路径: is_ipv6=1, 使用 sip6/dip6, sip/dip 存哈希值
 */
static void add_flow_stat(u_int sip, u_int dip, u_short sp, u_short dp,
                          u_char proto, int pkt_len,
                          int is_ipv6, const u_char *sip6, const u_char *dip6)
{
    flow5_key key;
    memset(&key, 0, sizeof(key));
    key.is_ipv6 = is_ipv6;
    key.sp = sp;
    key.dp = dp;
    key.proto = proto;

    if (is_ipv6 && sip6 && dip6) {
        memcpy(key.sip6, sip6, IPV6_LEN);
        memcpy(key.dip6, dip6, IPV6_LEN);
        key.sip = hash_ipv6_addr(sip6);
        key.dip = hash_ipv6_addr(dip6);
    } else {
        key.sip = sip;
        key.dip = dip;
    }

    flow_stat_add(&key, pkt_len);
}

/* ──────────────────────────────────────────────
 *  TLS 解析
 * ────────────────────────────────────────────── */

/*
 * parse_tls — 解析 TLS 记录
 *
 * 识别 ClientHello (SNI 提取) 和 ServerHello (密码套件信息提取)
 *   payload: TLS record 层数据
 *   len:     数据长度
 */
void parse_tls(const u_char *payload, int len)
{
    if (len < 6) return;
    if (payload[0] != 0x16) return;

    uint8_t hs_type = payload[5];
    if (hs_type == 0x01) {
        char sni[256] = {0};
        tls_extract_sni(payload, len, sni);
        if (sni[0] != '\0') {
            LOG_DEBUG("[TLS] ClientHello SNI: %s", sni);
        } else {
            LOG_DEBUG("[TLS] ClientHello detected (no SNI or record fragmented, len=%d)", len);
        }
    } else if (hs_type == 0x02) {
        char server_info[512] = {0};
        tls_parse_serverhello(payload, len, server_info);
        if (server_info[0] != '\0') {
            LOG_DEBUG("[TLS] ServerHello: %s", server_info);
        } else {
            LOG_DEBUG("[TLS] ServerHello detected");
        }
    }
}

/* ──────────────────────────────────────────────
 *  HTTP 载荷检测
 * ────────────────────────────────────────────── */

/*
 * parse_http_payload — 快速 HTTP 载荷检测
 *
 * 通过首行特征匹配 (GET/POST/HTTP/ 等) 识别 HTTP 流量
 *   payload: TCP/UDP 载荷起始地址
 *   len:     载荷长度
 */
static void parse_http_payload(const u_char *payload, int len)
{
    if (len < 5) return;

    if (!strncmp((const char *)payload, "GET ", 4) ||
        !strncmp((const char *)payload, "POST", 4) ||
        !strncmp((const char *)payload, "HEAD", 4) ||
        !strncmp((const char *)payload, "PUT ", 4) ||
        !strncmp((const char *)payload, "DELE", 4) ||
        !strncmp((const char *)payload, "OPTI", 4) ||
        !strncmp((const char *)payload, "CONN", 4) ||
        !strncmp((const char *)payload, "TRAC", 4) ||
        !strncmp((const char *)payload, "PATC", 4)) {
        stat_inc_http();
        int line_end = 0;
        for (int i = 0; i < len && i < 200; i++) {
            if (payload[i] == '\r' || payload[i] == '\n') { line_end = i; break; }
        }
        if (line_end > 0 && line_end < 200) {
            LOG_DEBUG("[HTTP-DIR] %.*s", line_end, payload);
        }
    } else if (!strncmp((const char *)payload, "HTTP/", 5)) {
        stat_inc_http();
        int line_end = 0;
        for (int i = 0; i < len && i < 200; i++) {
            if (payload[i] == '\r' || payload[i] == '\n') { line_end = i; break; }
        }
        if (line_end > 0 && line_end < 200) {
            LOG_DEBUG("[HTTP-DIR] %.*s", line_end, payload);
        }
    }
}

/*
 * parse_http — 公共接口: 解析 HTTP 载荷
 */
void parse_http(const u_char *payload, int len)
{
    parse_http_payload(payload, len);
}

/* ──────────────────────────────────────────────
 *  ICMP 解析
 * ────────────────────────────────────────────── */

/*
 * parse_icmp_payload — 解析 ICMP/ICMPv6 载荷
 */
static void parse_icmp_payload(const u_char *data, int len, u_int sip, u_int dip)
{
    (void)sip; (void)dip;
    if (len < (int)sizeof(struct icmp_hdr)) return;
    struct icmp_hdr *icmp = (struct icmp_hdr *)data;
    uint8_t type = icmp->type;
    uint8_t code = icmp->code;
    const char *type_str = "?";
    switch (type) {
        case 0:  type_str = "Echo Reply"; break;
        case 3:  type_str = "Dest Unreach"; break;
        case 5:  type_str = "Redirect"; break;
        case 8:  type_str = "Echo Request"; break;
        case 11: type_str = "TTL Exceeded"; break;
    }
    uint16_t icmp_id  = ntohs(icmp->id);
    uint16_t icmp_seq = ntohs(icmp->seq);
    (void)type_str; (void)code; (void)icmp_id; (void)icmp_seq;
    LOG_DEBUG("[ICMP] %s type=%d code=%d id=%u seq=%u",
             type_str, type, code, icmp_id, icmp_seq);
}

/* ──────────────────────────────────────────────
 *  UDP 解析
 * ────────────────────────────────────────────── */

/*
 * parse_udp — 解析 UDP 报文
 *
 * 提取端口号, 检测 HTTP/DNS 载荷
 *   sip:  IPv4 源地址 (IPv6 时为 0)
 *   dip:  IPv4 目标地址 (IPv6 时为 0)
 *   sip6: IPv6 源地址 (IPv4 时为 NULL)
 *   dip6: IPv6 目标地址 (IPv4 时为 NULL)
 */
void parse_udp(const u_char *data, int len, u_int sip, u_int dip,
               const u_char *sip6, const u_char *dip6)
{
    if (len < (int)sizeof(struct udp_hdr)) return;
    struct udp_hdr *udp = (struct udp_hdr *)data;
    u_short sport = ntohs(udp->sport);
    u_short dport = ntohs(udp->dport);
    int pay_len = len - (int)sizeof(struct udp_hdr);
    const u_char *pay = data + sizeof(struct udp_hdr);

    int is_ipv6 = (sip6 != NULL && dip6 != NULL);
    add_flow_stat(sip, dip, sport, dport, PROTO_UDP, len, is_ipv6, sip6, dip6);
    stat_inc_udp();

    if (dport == PORT_HTTP)
        parse_http_payload(pay, pay_len);
    if (sport == PORT_DNS || dport == PORT_DNS) {
        stat_inc_dns();
        parse_dns(pay, pay_len, sip, dip, sport, dport);
    }
}

/* ──────────────────────────────────────────────
 *  TCP 解析
 * ────────────────────────────────────────────── */

/*
 * parse_tcp — 解析 TCP 报文
 *
 * 提取端口号和序列号, 将载荷送入 tcp_flow_add 进行流重组,
 * 同时检测 HTTP/TLS 载荷
 *   sip:  IPv4 源地址 (IPv6 时为 0)
 *   dip:  IPv4 目标地址 (IPv6 时为 0)
 *   sip6: IPv6 源地址 (IPv4 时为 NULL)
 *   dip6: IPv6 目标地址 (IPv4 时为 NULL)
 */
void parse_tcp(const u_char *data, int len, u_int sip, u_int dip,
               const u_char *sip6, const u_char *dip6)
{
    if (len < (int)sizeof(struct tcp_hdr)) return;
    struct tcp_hdr *tcp = (struct tcp_hdr *)data;
    u_short sport = ntohs(tcp->sport);
    u_short dport = ntohs(tcp->dport);
    u_uint seq = ntohl(tcp->seq);
    u_int doff = tcp->doff * 4;
    if (doff < (u_int)sizeof(struct tcp_hdr) || (int)doff > len) {
        doff = sizeof(struct tcp_hdr);
    }
    int pay_len = len - (int)doff;
    const u_char *pay = data + doff;

    int is_ipv6 = (sip6 != NULL && dip6 != NULL);
    add_flow_stat(sip, dip, sport, dport, PROTO_TCP, len, is_ipv6, sip6, dip6);
    stat_inc_tcp();

    if (pay_len > 0) {
        if (dport == PORT_HTTP || sport == PORT_HTTP ||
            (pay_len >= 4 && (!strncmp((const char *)pay, "GET ", 4) ||
                              !strncmp((const char *)pay, "POST", 4) ||
                              !strncmp((const char *)pay, "HTTP", 4)))) {
            /* 送入 TCP 流重组: 支持 IPv4 和 IPv6 */
            tcp_flow_add(sip, dip, sip6, dip6, sport, dport, seq, pay, pay_len);
        }
        parse_http_payload(pay, pay_len);
    }
    if ((dport == PORT_HTTPS || sport == PORT_HTTPS) && pay_len > 0) {
        parse_tls(pay, pay_len);
    }
}

/* ──────────────────────────────────────────────
 *  IPv4 解析
 * ────────────────────────────────────────────── */

/*
 * parse_ipv4 — 解析 IPv4 报文头, 根据协议号分发到 TCP/UDP/ICMP
 */
void parse_ipv4(const u_char *data, int len)
{
    if (len < (int)sizeof(struct ipv4_hdr)) return;
    struct ipv4_hdr *ip = (struct ipv4_hdr *)data;
    int ihl = (ip->ihl & 0x0f) * 4;
    const u_char *trans_ptr = data + ihl;
    int trans_len = len - ihl;
    u_int sip = ntohl(ip->saddr);
    u_int dip = ntohl(ip->daddr);

    switch (ip->proto) {
        case PROTO_TCP:
            parse_tcp(trans_ptr, trans_len, sip, dip, NULL, NULL);
            break;
        case PROTO_UDP:
            parse_udp(trans_ptr, trans_len, sip, dip, NULL, NULL);
            break;
        case PROTO_ICMP:
            stat_inc_icmp();
            add_flow_stat(sip, dip, 0, 0, PROTO_ICMP, len, 0, NULL, NULL);
            parse_icmp_payload(trans_ptr, trans_len, sip, dip);
            break;
        default:
            break;
    }
}

/* ──────────────────────────────────────────────
 *  IPv6 解析  (修复: 不再使用 fake_ip=0)
 * ────────────────────────────────────────────── */

/*
 * parse_ipv6 — 解析 IPv6 报文头
 *
 * 修复: 不再统一赋 fake_ip=0, 而是完整传递 128 位 IPv6 地址,
 *       确保不同 IPv6 流被正确区分。
 */
void parse_ipv6(const u_char *data, int len)
{
    if (len < (int)sizeof(struct ipv6_hdr)) return;
    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)data;
    uint8_t next_hdr = ip6->next_hdr;
    int payload_len = ntohs(ip6->payload_len);
    const u_char *trans_data = data + sizeof(struct ipv6_hdr);

    /* 用 IPv6 地址 XOR 哈希作为 32 位标识 (用于内部键值) */
    u_int sip_hash = hash_ipv6_addr(ip6->saddr);
    u_int dip_hash = hash_ipv6_addr(ip6->daddr);

    switch (next_hdr) {
        case PROTO_TCP:
            parse_tcp(trans_data, payload_len, sip_hash, dip_hash,
                      ip6->saddr, ip6->daddr);
            break;
        case PROTO_UDP:
            parse_udp(trans_data, payload_len, sip_hash, dip_hash,
                      ip6->saddr, ip6->daddr);
            break;
        case PROTO_ICMPV6:
            stat_inc_icmp();
            add_flow_stat(sip_hash, dip_hash, 0, 0, PROTO_ICMPV6, payload_len,
                          1, ip6->saddr, ip6->daddr);
            parse_icmp_payload(trans_data, payload_len, sip_hash, dip_hash);
            break;
        default:
            break;
    }
}

/* ──────────────────────────────────────────────
 *  以太网帧解析
 * ────────────────────────────────────────────── */

/*
 * parse_eth — 解析以太网帧头, 根据 EtherType 分发
 */
void parse_eth(const u_char *data, int len)
{
    if (len < (int)sizeof(struct eth_hdr)) return;
    struct eth_hdr *eth = (struct eth_hdr *)data;
    u_short type = ntohs(eth->eth_type);
    const u_char *ip_ptr = data + sizeof(struct eth_hdr);
    int ip_len = len - (int)sizeof(struct eth_hdr);

    if (type == ETH_TYPE_IPV4)
        parse_ipv4(ip_ptr, ip_len);
    else if (type == ETH_TYPE_IPV6)
        parse_ipv6(ip_ptr, ip_len);
}

/*
 * parse_packet — 解析入口: 统计 + 以太网帧解析
 */
void parse_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
    stat_inc_total(hdr->len);
    parse_eth(data, hdr->len);
}
