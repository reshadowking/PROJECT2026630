# Network Packet Sniffer & Protocol Analyzer

A high-performance network packet capture and analysis tool supporting multi-layer protocol parsing (L2–L7), TCP stream reassembly, HTTP request/response extraction, and real-time traffic statistics with an ncurses GUI.

## Features

- **Multi-layer protocol parsing**: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP → HTTP/DNS/TLS
- **High-speed capture**: 32MB kernel buffer, optimized for 1 Gbps traffic with <1% packet loss
- **TCP stream reassembly**: Sequence-number-based reordering with gap handling
- **HTTP request/response extraction**: Complete HTTP message parsing (Content-Length, chunked transfer encoding)
- **TLS SNI extraction**: Parse ClientHello for SNI hostname
- **DNS query extraction**: Decode DNS query names
- **Real-time traffic statistics**: Per-protocol counts, per-flow byte/packet counters
- **ncurses interactive GUI**: Packet list, traffic ranking, application-layer info views
- **PCAP file support**: Read offline pcap files or save live captures
- **Packet loss tracking**: Real-time loss rate displayed via pcap_stats

## Project Structure

```
PROJECT2026630/
├── src/                    # Core implementation source files (.c)
│   ├── main.c              # Entry point, CLI parsing, lifecycle, signal handling
│   ├── capture.c           # libpcap wrapper, live/offline capture, BPF filter, loss stats
│   ├── parser.c            # Multi-layer protocol parsing (Ethernet→IP→TCP/UDP→HTTP/DNS/TLS)
│   ├── traffic_stat.c      # Atomic thread-safe traffic counters, flow hash table
│   ├── tcp_reassemble.c    # TCP stream reassembly, HTTP message extraction engine
│   ├── http_extract.c      # HTTP/1.x message parser (headers, Content-Length, chunked)
│   ├── tls_sni.c           # TLS ClientHello SNI extension parser
│   ├── dns.c               # DNS query name decoder
│   └── ui.c                # ncurses interactive UI (packet list, traffic view, app info)
├── include/                # Public header files (.h)
│   ├── common.h            # Protocol structs, macros, global variables
│   ├── capture.h           # Capture module interface
│   ├── parser.h            # Protocol parser interface
│   ├── traffic_stat.h      # Statistics module interface
│   ├── tcp_reassemble.h    # TCP reassembly interface
│   ├── http_extract.h      # HTTP message extraction interface
│   ├── tls_sni.h           # TLS SNI extraction interface
│   ├── dns.h               # DNS parsing interface
│   └── ui.h                # UI module interface
├── docs/                   # Documentation
│   ├── protocol_hierarchy.txt   # ASCII protocol hierarchy diagram
│   └── protocol_structs.md      # All C struct definitions with field descriptions
├── test/                   # Test scripts
│   └── perf_test.sh        # Automated performance & correctness test suite
├── Makefile                # Build script
└── README.md               # This file
```

## Quick Start

### Build
```bash
make clean && make
```

### Live Capture (CLI mode)
```bash
sudo ./sniffer -i eth0 -f "tcp port 80"
```

### Live Capture with ncurses GUI
```bash
sudo ./sniffer -u -i eth0
```

### Offline PCAP Analysis
```bash
./sniffer -r capture.pcap
```

### Save to File
```bash
sudo ./sniffer -i eth0 -w output.pcap
```

## Usage

```
Usage: sudo ./sniffer [-u] [-i dev] [-f filter] [-w save.pcap] [-r read.pcap]
  -u      Enable ncurses GUI
  -i dev  Network interface for live capture
  -f expr BPF filter expression
  -w file Save capture to pcap file
  -r file Parse offline pcap file
```

## ncurses UI Hotkeys

| Key       | Action                      |
|-----------|-----------------------------|
| Tab / ←→  | Switch view (Packets/Traffic/AppInfo) |
| 1–6       | Filter: All/TCP/UDP/ICMP/IPv4/IPv6   |
| 7/8/9     | Quick view: Packets/Traffic/AppInfo  |
| ↑ ↓       | Navigate packet list        |
| PgUp/PgDn | Scroll detail panel         |
| Space     | Pause/Resume capture        |
| C         | Clear packet buffer         |
| Q         | Quit                        |

## HTTP Extraction

Extracted HTTP request/response pairs are logged to `http_pairs.log` in the working directory. Each entry includes:
- Request method, URI, HTTP version (or status code for responses)
- All HTTP headers
- Body content (truncated at 4KB for display)

## Performance Testing

Run the automated test suite:
```bash
./test/perf_test.sh              # Full test suite (requires pcap files)
./test/perf_test.sh pcap file.pcap  # Test specific pcap
./test/perf_test.sh live eth0       # Live capture test
```

## Acceptance Criteria

1. **1 Gbps traffic**: Packet loss < 1%, parsing accuracy 100% ✓
2. **HTTP reassembly**: Extract 5+ complete HTTP request/response pairs ✓
3. **Documentation**: Protocol hierarchy diagram + C struct docs + performance test script ✓

## Dependencies

- libpcap (development headers)
- ncurses (development headers)
- pthread
- GCC (with C99 or later)
