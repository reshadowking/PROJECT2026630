#ifndef DNS_H
#define DNS_H
#include "common.h"

#define DNS_HDR_FLAGS_QR_MASK     0x8000
#define DNS_HDR_OPCODE_MASK      0x7800
#define DNS_HDR_AA_MASK          0x0400
#define DNS_HDR_TC_MASK          0x0200
#define DNS_HDR_RD_MASK          0x0100
#define DNS_HDR_RA_MASK          0x0080

// DNS头部
struct dns_hdr {
    u_short id;
    u_short flags;
    u_short qdcount;
    u_short ancount;
    u_short nscount;
    u_short arcount;
};

void parse_dns(const u_char *payload, int len);
#endif