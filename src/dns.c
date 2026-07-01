#include "dns.h"
#include <stdio.h>
// 简易域名打印
static void print_dns_name(const u_char *p, int total_len) {
    int off = 0;
    while (off < total_len) {
        u_char label_len = p[off];
        if (label_len == 0) break;
        if ((label_len & 0xC0) == 0xC0) {
            // 压缩指针，简易跳过不解析
            break;
        }
        if (off + label_len >= total_len) break;
        fwrite(p + off + 1, 1, label_len, stdout);
        putchar('.');
        off += label_len + 1;
    }
}
void parse_dns(const u_char *payload, int len) {
    if (len < sizeof(struct dns_hdr)) return;
    struct dns_hdr *dns = (struct dns_hdr *)payload;
    u_short id = ntohs(dns->id);
    u_short flags = ntohs(dns->flags);
    u_short qd = ntohs(dns->qdcount);
    u_short an = ntohs(dns->ancount); // 修复字段名：ancount 不是an
    printf("[DNS] ID:%u QR:%d QD:%d AN:%d ",
           id, (flags & DNS_HDR_FLAGS_QR_MASK) ? 1 : 0, qd, an); // 修复宏名
    // 跳DNS头部，打印查询域名
    const u_char *name_ptr = payload + sizeof(struct dns_hdr);
    print_dns_name(name_ptr, len - sizeof(struct dns_hdr));
    putchar('\n');
}