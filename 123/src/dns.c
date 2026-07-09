/*
 * dns.c — DNS 协议解析模块
 *
 * 功能:
 *   解析 DNS 查询/响应报文, 提取域名、查询类型、应答记录数
 *
 * 支持类型:
 *   A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV
 */

#include "dns.h"
#include "logger.h"

#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA   6
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_SRV   33

/*
 * decode_dns_name — 解码 DNS 域名 (支持指针压缩)
 *
 * DNS 域名使用标签编码: 每个标签前有一个字节表示长度,
 * 以 0x00 结尾。高两位为 11 表示指针跳转 (消息压缩)。
 *
 *   start:      DNS 消息起始地址 (用于指针跳转)
 *   payload:    当前读取位置
 *   total_len:  当前段剩余长度
 *   out:        输出缓冲区
 *   out_cap:    输出缓冲区容量
 *   return:     消费的字节数
 */
static int decode_dns_name(const u_char *start, const u_char *payload, int total_len,
                           char *out, int out_cap)
{
    int off = 0;
    int wrote = 0;
    int first = 1;
    int jumped = 0;
    int orig_off = 0;

    while (1) {
        if (off >= total_len) break;
        uint8_t label_len = payload[off];
        if (label_len == 0) {
            if (!jumped) orig_off = off + 1;
            break;
        }
        if ((label_len & 0xC0) == 0xC0) {
            /* 指针压缩 */
            if (off + 1 >= total_len) break;
            uint16_t ptr = ((label_len & 0x3F) << 8) | payload[off + 1];
            if (ptr >= total_len) break;
            if (!jumped) orig_off = off + 2;
            off = 0;
            payload = start;
            total_len = ptr + 128;
            jumped = 1;
            continue;
        }
        if (off + label_len >= total_len) break;
        if (!first && wrote < out_cap - 1) out[wrote++] = '.';
        first = 0;
        for (int i = 1; i <= label_len && wrote < out_cap - 1; i++)
            out[wrote++] = payload[off + i];
        off += label_len + 1;
        if (!jumped) orig_off = off;
    }
    out[wrote] = '\0';
    return jumped ? orig_off : off + (jumped ? 0 : 1);
}

/*
 * parse_dns — 解析 DNS 报文
 *
 *   payload: DNS 载荷起始地址
 *   len:     载荷长度
 *   sip:     源 IPv4 地址
 *   dip:     目标 IPv4 地址
 *   sp:      源端口
 *   dp:      目标端口
 */
void parse_dns(const u_char *payload, int len, u_int sip, u_int dip, u_short sp, u_short dp)
{
    (void)dip; (void)sp; (void)dp;

    if (len < (int)sizeof(struct dns_hdr)) return;
    struct dns_hdr *dns = (struct dns_hdr *)payload;
    u_short id = ntohs(dns->id);
    u_short flags = ntohs(dns->flags);
    u_short qdcount = ntohs(dns->qdcount);
    u_short ancount = ntohs(dns->ancount);
    int is_query = !(flags & DNS_HDR_FLAGS_QR_MASK);
    (void)id; (void)qdcount; (void)ancount; (void)is_query;

    char name[256] = {0};
    int name_off = 12;
    int end = decode_dns_name(payload, payload + name_off, len - name_off, name, sizeof(name));
    int ptr = name_off + end;

    uint16_t qtype = 0;
    if (ptr + 2 <= len) {
        qtype = (payload[ptr] << 8) | payload[ptr + 1];
    }

    const char *type_str = "?";
    switch (qtype) {
        case DNS_TYPE_A:     type_str = "A";     break;
        case DNS_TYPE_NS:    type_str = "NS";    break;
        case DNS_TYPE_CNAME: type_str = "CNAME"; break;
        case DNS_TYPE_SOA:   type_str = "SOA";   break;
        case DNS_TYPE_PTR:   type_str = "PTR";   break;
        case DNS_TYPE_MX:    type_str = "MX";    break;
        case DNS_TYPE_TXT:   type_str = "TXT";   break;
        case DNS_TYPE_AAAA:  type_str = "AAAA";  break;
        case DNS_TYPE_SRV:   type_str = "SRV";   break;
    }

    (void)type_str;
    if (is_query) {
        char sip_str[INET_ADDRSTRLEN] = {0};
        struct in_addr sa;
        sa.s_addr = htonl(sip);
        inet_ntop(AF_INET, &sa, sip_str, sizeof(sip_str));
        LOG_DEBUG("[DNS-QUERY] id=%u %s %s from %s", id, name, type_str, sip_str);
    } else {
        LOG_DEBUG("[DNS-RESP] id=%u %s %s an=%u", id, name, type_str, ancount);
    }
}
