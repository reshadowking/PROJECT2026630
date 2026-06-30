#ifndef PARSER_H
#define PARSER_H
#include "common.h"

void parse_packet(const struct pcap_pkthdr *hdr, const u_char *data);
void parse_eth(const u_char *data, int len);
void parse_ipv4(const u_char *data, int len);
void parse_tcp(const u_char *data, int len, u_int sip, u_int dip);
void parse_udp(const u_char *data, int len, u_int sip, u_int dip);
void parse_http(const u_char *payload, int len);
void parse_tls(const u_char *payload, int len);

#endif