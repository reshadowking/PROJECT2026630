#ifndef PARSER_H
#define PARSER_H
#include "common.h"

/*
 * parse_packet — 入口: 解析一个 pcap 报文
 *   hdr:  pcap 报文头
 *   data: 原始报文数据
 */
void parse_packet(const struct pcap_pkthdr *hdr, const u_char *data);

/*
 * parse_eth — 解析以太网帧, 根据 EtherType 分发到 IPv4/IPv6
 *   data: 以太网帧起始地址
 *   len:  帧长度
 */
void parse_eth(const u_char *data, int len);

/*
 * parse_ipv4 — 解析 IPv4 报文
 *   data: IP 头起始地址
 *   len:  IP 报文长度
 */
void parse_ipv4(const u_char *data, int len);

/*
 * parse_ipv6 — 解析 IPv6 报文
 *   data: IPv6 头起始地址
 *   len:  IPv6 报文长度
 */
void parse_ipv6(const u_char *data, int len);

/*
 * parse_tcp — 解析 TCP 报文
 *   data: TCP 头起始地址
 *   len:  TCP 报文长度
 *   sip:  源 IPv4 地址 (IPv6 时为 0)
 *   dip:  目标 IPv4 地址 (IPv6 时为 0)
 *   sip6: 源 IPv6 地址 (IPv4 时为 NULL)
 *   dip6: 目标 IPv6 地址 (IPv4 时为 NULL)
 */
void parse_tcp(const u_char *data, int len, u_int sip, u_int dip,
               const u_char *sip6, const u_char *dip6);

/*
 * parse_udp — 解析 UDP 报文
 *   sip:  源 IPv4 地址 (IPv6 时为 0)
 *   dip:  目标 IPv4 地址 (IPv6 时为 0)
 *   sip6: 源 IPv6 地址 (IPv4 时为 NULL)
 *   dip6: 目标 IPv6 地址 (IPv4 时为 NULL)
 */
void parse_udp(const u_char *data, int len, u_int sip, u_int dip,
               const u_char *sip6, const u_char *dip6);

/*
 * parse_http — 解析 HTTP 载荷 (直接检测)
 *   payload: TCP/UDP 载荷起始地址
 *   len:     载荷长度
 */
void parse_http(const u_char *payload, int len);

/*
 * parse_tls — 识别并解析 TLS 握手记录
 *   payload: TLS 记录起始地址
 *   len:     载荷长度
 */
void parse_tls(const u_char *payload, int len);
#endif
