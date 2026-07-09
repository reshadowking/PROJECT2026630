# Protocol C Struct Definitions — Network Sniffer

## Overview

This document defines all C structures used in the network protocol sniffer for parsing Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, and TLS/HTTP application-layer data.

---

## 1. Ethernet Header (`struct eth_hdr`)

Defined in: `include/common.h:38`

| Field    | Type      | Size | Offset | Description                          |
|----------|-----------|------|--------|--------------------------------------|
| dst_mac  | u_char[6] | 6    | 0      | Destination MAC address              |
| src_mac  | u_char[6] | 6    | 6      | Source MAC address                   |
| eth_type | u_short   | 2    | 12     | EtherType (0x0800=IPv4, 0x86DD=IPv6) |

```c
struct eth_hdr {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
};
```

**Total size: 14 bytes**

**Constants:**
| Name           | Value    | Description      |
|----------------|----------|------------------|
| ETH_TYPE_IPV4  | 0x0800   | IPv4 payload     |
| ETH_TYPE_IPV6  | 0x86DD   | IPv6 payload     |
| MAC_LEN        | 6        | MAC addr length  |

---

## 2. IPv4 Header (`struct ipv4_hdr`)

Defined in: `include/common.h:47`

| Field     | Type     | Size | Offset | Description                         |
|-----------|----------|------|--------|-------------------------------------|
| ihl       | u_char:4 | 4b   | 0[0:3] | Internet Header Length (×4 bytes)   |
| ver       | u_char:4 | 4b   | 0[4:7] | IP version (4)                      |
| tos       | u_char   | 1    | 1      | Type of Service                     |
| total_len | u_short  | 2    | 2      | Total datagram length (bytes)       |
| id        | u_short  | 2    | 4      | Identification (fragmentation)      |
| frag_off  | u_short  | 2    | 6      | Fragment offset + flags             |
| ttl       | u_char   | 1    | 8      | Time to Live                        |
| proto     | u_char   | 1    | 9      | Transport protocol number           |
| check     | u_short  | 2    | 10     | Header checksum                     |
| saddr     | u_int    | 4    | 12     | Source IPv4 address                 |
| daddr     | u_int    | 4    | 16     | Destination IPv4 address            |

```c
struct ipv4_hdr {
    u_char ihl:4, ver:4;
    u_char tos;
    u_short total_len;
    u_short id;
    u_short frag_off;
    u_char ttl;
    u_char proto;
    u_short check;
    u_int saddr;
    u_int daddr;
};
```

**Total size: 20 bytes (typical, without options)**

**Protocol constants:**
| Name         | Value | Description   |
|--------------|-------|---------------|
| PROTO_TCP    | 6     | TCP           |
| PROTO_UDP    | 17    | UDP           |
| PROTO_ICMP   | 1     | ICMP          |
| PROTO_ICMPV6 | 58    | ICMPv6        |

---

## 3. IPv6 Header (`struct ipv6_hdr`)

Defined in: `include/common.h:61`

| Field        | Type      | Size | Offset | Description                      |
|--------------|-----------|------|--------|----------------------------------|
| ver_tc_flow  | u_uint    | 4    | 0      | Version(4)+TrafficClass+FlowLabel|
| payload_len  | u_short   | 2    | 4      | Payload length (bytes)           |
| next_hdr     | u_char    | 1    | 6      | Next header (proto number)       |
| hop_limit    | u_char    | 1    | 7      | Hop limit                        |
| saddr        | u_char[16]| 16   | 8      | Source IPv6 address              |
| daddr        | u_char[16]| 16   | 24     | Destination IPv6 address         |

```c
struct ipv6_hdr {
    u_uint ver_tc_flow;
    u_short payload_len;
    u_char next_hdr;
    u_char hop_limit;
    u_char saddr[16];
    u_char daddr[16];
};
```

**Total size: 40 bytes**

---

## 4. TCP Header (`struct tcp_hdr`)

Defined in: `include/common.h:75`

| Field  | Type     | Size | Offset | Description                          |
|--------|----------|------|--------|--------------------------------------|
| sport  | u_short  | 2    | 0      | Source port                          |
| dport  | u_short  | 2    | 2      | Destination port                     |
| seq    | u_uint   | 4    | 4      | Sequence number                      |
| ack    | u_uint   | 4    | 8      | Acknowledgment number                |
| res    | u_char:4 | 4b   | 12[0:3]| Reserved (unused)                    |
| doff   | u_char:4 | 4b   | 12[4:7]| Data offset (header len ÷ 4)         |
| flags  | u_char   | 1    | 13     | Control flags                        |
| win    | u_short  | 2    | 14     | Window size                          |
| check  | u_short  | 2    | 16     | Checksum                             |
| urg    | u_short  | 2    | 18     | Urgent pointer                       |

```c
struct tcp_hdr {
    u_short sport;
    u_short dport;
    u_uint seq;
    u_uint ack;
    u_char res:4, doff:4;
    u_char flags;
    u_short win;
    u_short check;
    u_short urg;
};
```

**Total size: 20 bytes (typical, without options)**

**TCP payload offset: `doff * 4` bytes**

**Flag constants:**
| Name    | Value | Description |
|---------|-------|-------------|
| TCP_FIN | 0x01  | Finish      |
| TCP_SYN | 0x02  | Synchronize |
| TCP_RST | 0x04  | Reset       |
| TCP_PSH | 0x08  | Push        |
| TCP_ACK | 0x10  | Acknowledge |

---

## 5. UDP Header (`struct udp_hdr`)

Defined in: `include/common.h:93`

| Field  | Type    | Size | Offset | Description      |
|--------|---------|------|--------|------------------|
| sport  | u_short | 2    | 0      | Source port      |
| dport  | u_short | 2    | 2      | Destination port |
| len    | u_short | 2    | 4      | UDP length       |
| check  | u_short | 2    | 6      | Checksum         |

```c
struct udp_hdr {
    u_short sport;
    u_short dport;
    u_short len;
    u_short check;
};
```

**Total size: 8 bytes**

---

## 6. ICMP Header (`struct icmp_hdr`)

Defined in: `include/common.h:101`

| Field | Type    | Size | Offset | Description     |
|-------|---------|------|--------|-----------------|
| type  | u_char  | 1    | 0      | ICMP type       |
| code  | u_char  | 1    | 1      | ICMP code       |
| check | u_short | 2    | 2      | Checksum        |
| id    | u_short | 2    | 4      | Identifier      |
| seq   | u_short | 2    | 6      | Sequence number |

```c
struct icmp_hdr {
    u_char type;
    u_char code;
    u_short check;
    u_short id;
    u_short seq;
};
```

**Total size: 8 bytes**

---

## 7. DNS Header (`struct dns_hdr`)

Defined in: `include/dns.h:13`

| Field   | Type    | Size | Offset | Description              |
|---------|---------|------|--------|--------------------------|
| id      | u_short | 2    | 0      | Transaction ID           |
| flags   | u_short | 2    | 2      | Flags (QR, Opcode, etc.) |
| qdcount | u_short | 2    | 4      | Question count           |
| ancount | u_short | 2    | 6      | Answer count             |
| nscount | u_short | 2    | 8      | Authority count          |
| arcount | u_short | 2    | 10     | Additional count         |

```c
struct dns_hdr {
    u_short id;
    u_short flags;
    u_short qdcount;
    u_short ancount;
    u_short nscount;
    u_short arcount;
};
```

**Total size: 12 bytes**

---

## 8. Traffic Statistics (`traffic_stat`)

Defined in: `include/common.h:137`

```c
typedef struct {
    u_int  pkt_tcp;       // TCP packet count
    u_int  pkt_udp;       // UDP packet count
    u_int  pkt_icmp;      // ICMP packet count
    u_int  pkt_http;      // HTTP packet count
    u_int  pkt_http_req;  // HTTP request count (extracted)
    u_int  pkt_http_resp; // HTTP response count (extracted)
    u_int  pkt_dns;       // DNS packet count
    u_int  pkt_total;     // Total packet count
    u_long byte_total;    // Total bytes captured
} traffic_stat;
```

---

## 9. Flow Key Structures

### TCP flow key (`tcp_flow_key`)
Defined in: `include/common.h:110`
```c
typedef struct {
    u_int  sip;   // Source IP
    u_int  dip;   // Destination IP
    u_short sp;   // Source port
    u_short dp;   // Destination port
} tcp_flow_key;
```

### 5-tuple flow key (`flow5_key`)
Defined in: `include/common.h:118`
```c
typedef struct {
    u_int  sip;    // Source IP
    u_int  dip;    // Destination IP
    u_short sp;    // Source port
    u_short dp;    // Destination port
    u_char proto;  // Protocol
} flow5_key;
```

---

## 10. HTTP Message (`http_message`)

Defined in: `include/http_extract.h`

```c
typedef struct {
    http_msg_type type;           // REQUEST or RESPONSE

    // Request fields
    char method[16];              // GET, POST, etc.
    char uri[2048];               // Request URI
    char version[16];             // HTTP/1.0, HTTP/1.1

    // Response fields
    int  status_code;             // 200, 404, etc.
    char reason[64];              // OK, Not Found, etc.

    // Headers
    http_header_line headers[64]; // Parsed header lines
    int  header_count;

    // Body
    int  content_length;          // From Content-Length header (-1=chunked)
    u_char *body;                 // Body buffer (dynamically allocated)
    int  body_len;
    int  body_complete;

    // Chunked state
    int  chunked;
    int  chunk_state;
    int  chunk_remaining;
} http_message;
```

---

## 11. TCP Reassembly Structures (Internal)

### Per-direction buffer (`dir_buf`)
Defined in: `src/tcp_reassemble.c`

```c
typedef struct {
    u_char *buf;          // Dynamic buffer (64KB–2MB)
    int     cap;          // Current capacity
    int     len;          // Valid data length
    u_int   base_seq;     // Sequence number of buf[0]
    u_int   next_seq;     // Next expected sequence number
    int     fin_received;  // FIN flag received
    int     syn_received;  // SYN flag received
    int     data_started;  // Has payload data started

    http_message http_msg; // HTTP parser state
    int http_headers_done; // Headers fully parsed
    int http_complete;     // Message fully extracted
} dir_buf;
```

### Bidirectional TCP flow (`tcp_flow`)
```c
typedef struct {
    tcp_flow_key  key;     // Client→Server direction
    tcp_flow_key  rev_key; // Server→Client direction
    dir_buf       c2s;     // Client→Server data buffer
    dir_buf       s2c;     // Server→Client data buffer
    time_t        last_active;
    int           active;
    int           http_extracted; // Extracted pair counter
} tcp_flow;
```

**Constants:**
| Name          | Value       | Description               |
|---------------|-------------|---------------------------|
| MAX_FLOWS     | 256         | Max concurrent TCP flows  |
| DIR_BUF_INIT  | 65536 (64KB)| Initial buffer per dir    |
| DIR_BUF_MAX   | 2097152 (2MB)| Max buffer per dir       |
| FLOW_TIMEOUT  | 120         | Idle flow timeout (sec)   |
