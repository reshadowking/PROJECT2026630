#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "tls_sni.h"
#include "dns.h"
#include "ui.h"

static void add_flow_stat(u_int sip, u_int dip, u_short sp, u_short dp, u_char proto, int pkt_len) {
    flow5_key key = {sip, dip, sp, proto};
    flow_stat_add(&key, pkt_len);
}

/* Parse TLS ClientHello and extract SNI.
 * If 'sni_out' is non-NULL, writes the SNI hostname there (up to sni_sz bytes). */
void parse_tls(const u_char *payload, int len, char *sni_out, int sni_sz)
{
    if (len < 6) return;
    if (payload[0] != 0x16 || payload[5] != 0x01) return; /* not ClientHello */

    if (sni_out && sni_sz > 0) {
        tls_extract_sni(payload, len, sni_out);
    }
}

/* Parse HTTP request line and extract the method.
 * If 'method_out' is non-NULL, writes the method string (e.g. "GET") there. */
void parse_http(const u_char *payload, int len, char *method_out, int method_sz)
{
    if (len < 4) return;

    /* Recognise common HTTP methods */
    static const char *methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELETE",
                                    "PATCH", "OPTIONS", "CONNECT", "TRACE"};
    int n_methods = sizeof(methods) / sizeof(methods[0]);
    int i;
    for (i = 0; i < n_methods; i++) {
        if (!strncmp((const char *)payload, methods[i], strlen(methods[i]))) {
            stat_inc_http();
            if (method_out && method_sz > 0) {
                int mlen = strlen(methods[i]) - 1; /* strip trailing space */
                strncpy(method_out, methods[i], mlen);
                method_out[mlen] = '\0';
            }
            return;
        }
    }
}

void parse_udp(const u_char *data, int len, u_int sip, u_int dip,
               char *dns_domain, int domain_sz)
{
    if (len < (int)sizeof(struct udp_hdr)) return;

    struct udp_hdr *udp = (struct udp_hdr *)data;
    u_short sport = ntohs(udp->sport);
    u_short dport = ntohs(udp->dport);
    int pay_len = len - (int)sizeof(struct udp_hdr);
    const u_char *pay = data + sizeof(struct udp_hdr);

    add_flow_stat(sip, dip, sport, dport, PROTO_UDP, len);
    stat_inc_udp();

    /* DNS */
    if (sport == PORT_DNS || dport == PORT_DNS) {
        stat_inc_dns();
        parse_dns(pay, pay_len, dns_domain, domain_sz);
    }

    /* HTTP over UDP (rare but possible, e.g. alt-svc) */
    if (dport == PORT_HTTP || sport == PORT_HTTP) {
        parse_http(pay, pay_len, NULL, 0);
    }
}

void parse_tcp(const u_char *data, int len, u_int sip, u_int dip,
               char *tls_sni, int sni_sz, char *http_method, int method_sz)
{
    if (len < (int)sizeof(struct tcp_hdr)) return;

    struct tcp_hdr *tcp = (struct tcp_hdr *)data;
    u_short sport = ntohs(tcp->sport);
    u_short dport = ntohs(tcp->dport);
    u_uint seq = ntohl(tcp->seq);
    int doff = (tcp->doff >> 4) * 4;
    int pay_len = len - doff;
    const u_char *pay = data + doff;

    add_flow_stat(sip, dip, sport, dport, PROTO_TCP, len);
    stat_inc_tcp();

    /* TCP flow reassembly for HTTP/TLS ports */
    if (dport == PORT_HTTP || sport == PORT_HTTP ||
        dport == PORT_HTTPS || sport == PORT_HTTPS) {
        tcp_flow_add(sip, dip, sport, dport, seq, pay, pay_len);
    }

    /* HTTP method extraction */
    if (dport == PORT_HTTP || sport == PORT_HTTP) {
        parse_http(pay, pay_len, http_method, method_sz);
    }

    /* TLS SNI extraction */
    if (dport == PORT_HTTPS || sport == PORT_HTTPS) {
        parse_tls(pay, pay_len, tls_sni, sni_sz);
    }
}

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
            parse_tcp(trans_ptr, trans_len, sip, dip, NULL, 0, NULL, 0);
            break;
        case PROTO_UDP:
            parse_udp(trans_ptr, trans_len, sip, dip, NULL, 0);
            break;
        case PROTO_ICMP:
            stat_inc_icmp();
            add_flow_stat(sip, dip, 0, 0, PROTO_ICMP, len);
            break;
    }
}

/* Full functional IPv6 parser */
void parse_ipv6(const u_char *data, int len)
{
    if (len < (int)sizeof(struct ipv6_hdr)) return;

    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)data;
    uint8_t next_hdr = ip6->next_hdr;
    int payload_len = ntohs(ip6->payload_len);
    const u_char *trans_data = data + sizeof(struct ipv6_hdr);

    uint64_t sip6_hi = ((uint64_t)ip6->saddr[0] << 56) | ((uint64_t)ip6->saddr[1] << 48)
        | ((uint64_t)ip6->saddr[2] << 40) | ((uint64_t)ip6->saddr[3] << 32)
        | ((uint64_t)ip6->saddr[4] << 24) | ((uint64_t)ip6->saddr[5] << 16)
        | ((uint64_t)ip6->saddr[6] << 8) | ip6->saddr[7];
    uint64_t dip6_hi = ((uint64_t)ip6->daddr[0] << 56) | ((uint64_t)ip6->daddr[1] << 48)
        | ((uint64_t)ip6->daddr[2] << 40) | ((uint64_t)ip6->daddr[3] << 32)
        | ((uint64_t)ip6->daddr[4] << 24) | ((uint64_t)ip6->daddr[5] << 16)
        | ((uint64_t)ip6->daddr[6] << 8) | ip6->daddr[7];

    switch (next_hdr) {
        case 6:   /* TCP */
            parse_tcp(trans_data, payload_len,
                      (u_int)sip6_hi, (u_int)dip6_hi,
                      NULL, 0, NULL, 0);
            break;
        case 17:  /* UDP */
            parse_udp(trans_data, payload_len,
                      (u_int)sip6_hi, (u_int)dip6_hi,
                      NULL, 0);
            break;
        case 58:  /* ICMPv6 */
            stat_inc_icmp();
            add_flow_stat((u_int)sip6_hi, (u_int)dip6_hi, 0, 0, 58, payload_len);
            break;
    }
}

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

void parse_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
    stat_inc_total(hdr->len);
    parse_eth(data, hdr->len);
}
