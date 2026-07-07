#include "dns.h"
static void print_dns_name(const u_char *p, int total_len) {
    int off = 0;
    while (off < total_len) {
        u_char label_len = p[off];
        if (label_len == 0) break;
        if ((label_len & 0xC0) == 0xC0) break;
        if (off + label_len >= total_len) break;
        off += label_len + 1;
    }
}
void parse_dns(const u_char *payload, int len) {
    if (len < sizeof(struct dns_hdr)) return;
    struct dns_hdr *dns = (struct dns_hdr *)payload;
    (void)ntohs(dns->id);
    (void)ntohs(dns->flags);
    (void)ntohs(dns->qdcount);
    (void)ntohs(dns->ancount);
    const u_char *name_ptr = payload + sizeof(struct dns_hdr);
    print_dns_name(name_ptr, len - sizeof(struct dns_hdr));
}