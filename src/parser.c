#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "tls_sni.h"

traffic_stat g_stat = {0};

void parse_packet(const struct pcap_pkthdr *hdr, const u_char *data) {
    g_stat.pkt_total++;
    g_stat.byte_total += hdr->len;
    printf("\n====================\n[数据包总长度：%d]\n", hdr->len);
    parse_eth(data, hdr->len);
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
        printf("[IPv6 报文，暂不解析]\n");
}

void parse_ipv4(const u_char *data, int len) {
    if (len < sizeof(struct ipv4_hdr))
        return;
    // 修复1：之前少* 语法报错
    struct ipv4_hdr *ip = (struct ipv4_hdr *)data;
    int ihl = (ip->ihl & 0x0f) * 4;
    const u_char *trans_ptr = data + ihl;
    int trans_len = len - ihl;
    u_int sip = ntohl(ip->saddr);
    u_int dip = ntohl(ip->daddr);
    printf("IPv4 源IP:%u 目的IP:%u ", sip, dip);
    switch (ip->proto) {
        case PROTO_TCP:
            g_stat.pkt_tcp++;
            parse_tcp(trans_ptr, trans_len, sip, dip);
            break;
        case PROTO_UDP:
            g_stat.pkt_udp++;
            parse_udp(trans_ptr, trans_len, sip, dip);
            break;
        case PROTO_ICMP:
            g_stat.pkt_icmp++;
            printf("协议：ICMP\n");
            break;
    }
}

void parse_tcp(const u_char *data, int len, u_int sip, u_int dip) {
    if (len < sizeof(struct tcp_hdr))
        return;
    struct tcp_hdr *tcp = (struct tcp_hdr *)data;
    int doff = (tcp->doff >> 4) * 4;
    u_short sport = ntohs(tcp->sport);
    u_short dport = ntohs(tcp->dport);
    int pay_len = len - doff;
    const u_char *pay = data + doff;
    printf("TCP 源端口:%d 目的端口:%d 序列号:%u\n", sport, dport, ntohl(tcp->seq));
    tcp_flow_add(sip, dip, sport, dport, ntohl(tcp->seq), (u_char *)pay, pay_len);
    if (dport == 80 || sport == 80)
        parse_http(pay, pay_len);
    if (dport == 443 || sport == 443)
        parse_tls(pay, pay_len);
}

void parse_udp(const u_char *data, int len, u_int sip, u_int dip) {
    if (len < sizeof(struct udp_hdr))
        return;
    struct udp_hdr *udp = (struct udp_hdr *)data;
    // 修复2：之前错写成tcp->sport
    u_short sport = ntohs(udp->sport);
    u_short dport = ntohs(udp->dport);
    int pay_len = len - sizeof(struct udp_hdr);
    const u_char *pay = data + sizeof(struct udp_hdr);
    printf("UDP 源端口:%d 目的端口:%d\n", sport, dport);
    if (dport == 80)
        parse_http(pay, pay_len);
}

void parse_http(const u_char *payload, int len) {
    if (len < 4)
        return;
    if (!strncmp((const char *)payload, "GET ", 4) || !strncmp((const char *)payload, "POST", 4)) {
        g_stat.pkt_http++;
        printf("[HTTP 载荷] %.*s\n", len > 128 ? 128 : len, payload);
    }
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