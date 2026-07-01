#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "tls_sni.h"
#include "dns.h"

static void add_flow_stat(u_int sip, u_int dip, u_short sp, u_short dp, u_char proto, int pkt_len) {
    flow5_key key = {sip, dip, sp, dp, proto};
    flow_stat_add(&key, pkt_len);
}

void parse_tls(const u_char *payload, int len) {
    if (len < 5)
        return;
    if (payload[0] == 0x16 && payload[5] == 0x01) {
        char sni[256] = {0};
        tls_extract_sni(payload, len, sni);
        if (strlen(sni))
            printf("[TLS SNI 域名] %s\n", sni);
    }
}

void parse_http(const u_char *payload, int len) {
    if (len < 4)
        return;
    if (!strncmp((const char *)payload, "GET ", 4) || !strncmp((const char *)payload, "POST", 4)) {
        stat_inc_http();
        printf("[HTTP 载荷] %.*s\n", len > 128 ? 128 : len, payload);
    }
}

void parse_udp(const u_char *data, int len, u_int sip, u_int dip) {
    if (len < sizeof(struct udp_hdr))
        return;
    struct udp_hdr *udp = (struct udp_hdr *)data;
    u_short sport = ntohs(udp->sport);
    u_short dport = ntohs(udp->dport);
    int pay_len = len - sizeof(struct udp_hdr);
    const u_char *pay = data + sizeof(struct udp_hdr);

    add_flow_stat(sip, dip, sport, dport, PROTO_UDP, len);
    stat_inc_udp();
    printf("UDP 源端口:%d 目的端口:%d\n", sport, dport);

    if (dport == PORT_HTTP)
        parse_http(pay, pay_len);
    if (sport == PORT_DNS || dport == PORT_DNS) {
        stat_inc_dns();
        parse_dns(pay, pay_len);
    }
}

// parse_tcp 入参只传 sip dip，端口内部从tcp头读取
void parse_tcp(const u_char *data, int len, u_int sip, u_int dip) {
    if (len < sizeof(struct tcp_hdr))
        return;
    struct tcp_hdr *tcp = (struct tcp_hdr *)data;
    u_short sport = ntohs(tcp->sport);
    u_short dport = ntohs(tcp->dport);
    u_uint seq = ntohl(tcp->seq);
    int doff = (tcp->doff >> 4) * 4;
    int pay_len = len - doff;
    const u_char *pay = data + doff;

    add_flow_stat(sip, dip, sport, dport, PROTO_TCP, len);
    stat_inc_tcp();
    printf("TCP 源端口:%d 目的端口:%d 序列号:%u\n", sport, dport, seq);

    // 参数顺序完全匹配头文件：sip,dip,sp,dp,seq,pay,len
    tcp_flow_add(sip, dip, sport, dport, seq, pay, pay_len);

    if (dport == PORT_HTTP || sport == PORT_HTTP)
        parse_http(pay, pay_len);
    if (dport == PORT_HTTPS || sport == PORT_HTTPS)
        parse_tls(pay, pay_len);
}


void parse_ipv4(const u_char *data, int len) {
    if (len < sizeof(struct ipv4_hdr))
        return;
    struct ipv4_hdr *ip = (struct ipv4_hdr *)data;
    int ihl = (ip->ihl & 0x0f) * 4;
    const u_char *trans_ptr = data + ihl;
    int trans_len = len - ihl;
    u_int sip = ntohl(ip->saddr);
    u_int dip = ntohl(ip->daddr);

    // 转成点分十进制IP字符串
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
    printf("IPv4 源IP:%s 目的IP:%s ", src_ip, dst_ip);

    switch (ip->proto) {
        case PROTO_TCP:
            parse_tcp(trans_ptr, trans_len, sip, dip);
            break;
        case PROTO_UDP:
            parse_udp(trans_ptr, trans_len, sip, dip);
            break;
        case PROTO_ICMP:
            stat_inc_icmp();
            add_flow_stat(sip, dip, 0, 0, PROTO_ICMP, len);
            printf("协议：ICMP\n");
            break;
    }
}



void parse_ipv6(const u_char *data, int len) {
    if (len < sizeof(struct ipv6_hdr)) return;
    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)data;
    u_char next = ip6->next_hdr;
    char s[40], d[40];
    inet_ntop(AF_INET6, ip6->saddr, s, sizeof(s));
    inet_ntop(AF_INET6, ip6->daddr, d, sizeof(d));
    printf("[IPv6] src:%s dst:%s next_hdr:%d\n", s, d, next);
}

void parse_eth(const u_char *data, int len) {
    if (len < sizeof(struct eth_hdr))
        return;
    struct eth_hdr *eth = (struct eth_hdr *)data;
    u_short type = ntohs(eth->eth_type);
    const u_char *ip_ptr = data + sizeof(struct eth_hdr);
    int ip_len = len - sizeof(struct eth_hdr);
    if (type == ETH_TYPE_IPV4)
        parse_ipv4(ip_ptr, ip_len);
    else if (type == ETH_TYPE_IPV6)
        parse_ipv6(ip_ptr, ip_len);
}

void parse_packet(const struct pcap_pkthdr *hdr, const u_char *data) {
    stat_inc_total(hdr->len);
    printf("\n====================\n[数据包总长度：%d]\n", hdr->len);
    parse_eth(data, hdr->len);
}