# ZQ - 网络数据包捕获与协议解析工具

轻量级 Wireshark 替代品，基于 libpcap 实现抓包、逐层协议解析、TCP 流重组和实时流量统计。

## 功能特性

### 基础功能
- **抓包引擎**：基于 libpcap，支持网卡混杂模式、大内核缓冲区 (256MB)、immediate mode
- **协议解析**：Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ICMPv6 / DNS / HTTP / TLS
- **BPF 过滤**：支持 `pcap_compile` 过滤规则 (如 `tcp port 80 and host 192.168.1.1`)
- **流量统计**：按协议类型 / IP 对实时统计报文数、字节数，每秒刷新
- **PCAP 读写**：支持从 .pcap 文件回放，以及将捕获流量写入文件

### 进阶功能
- **TCP 流重组**：基于序列号拼接 TCP 载荷，支持 OOO 乱序重排，动态可扩容缓冲区 (初始 8KB, 上限 2MB)
- **HTTP 解析**：完整请求/响应解析，分块传输编码 (chunked) 自动解码，请求-响应配对日志
- **TLS 握手识别**：解析 ClientHello 提取 SNI 域名，解析 ServerHello 提取密码套件
- **终端 UI**：ncurses 实时界面，支持多标签页、协议过滤、报文列表滚动

## 编译

### 依赖
```bash
# Debian/Ubuntu
sudo apt-get install build-essential libpcap-dev libncurses-dev

# RHEL/CentOS
sudo yum install gcc libpcap-devel ncurses-devel
```

### 编译命令
```bash
# Release 版本 (INFO 级别日志)
make

# Debug 版本 (DEBUG 级别日志，输出详细解析信息)
make debug

# 清理
make clean
```

编译选项：`-Wall -Wextra -O3 -march=native -g -pthread`

编译产物：`./sniffer`

## 运行

### 命令行参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-u` | 启用 ncurses 图形 UI | `-u` |
| `-i dev` | 指定网卡实时抓包 | `-i eth0` |
| `-f expr` | BPF 过滤表达式 | `-f "tcp port 80"` |
| `-w file` | 保存抓包到 pcap 文件 | `-w capture.pcap` |
| `-r file` | 读取 pcap 文件离线回放 | `-r test.pcap` |

### 使用示例

```bash
# 实时抓包 (文本模式)
sudo ./sniffer -i eth0

# 实时抓包 + BPF 过滤 + UI
sudo ./sniffer -u -i eth0 -f "tcp port 80"

# 离线回放 pcap 文件
./sniffer -r capture.pcap

# 抓包并保存到文件
sudo ./sniffer -i lo -w output.pcap

# Debug 模式 (详细日志输出到 stderr)
make debug && sudo ./sniffer -i lo -f "port 53"
```

### UI 操作按键

| 按键 | 功能 |
|------|------|
| `TAB` | 切换标签页 (报文列表 / 流量统计 / 应用层信息) |
| `1` | 过滤：显示全部报文 |
| `2` | 过滤：仅 TCP |
| `3` | 过滤：仅 UDP |
| `4` | 过滤：仅 ICMP |
| `5` | 过滤：仅 IPv4 |
| `6` | 过滤：仅 IPv6 |
| `↑` `↓` | 选择报文 |
| `PgUp` `PgDn` | 翻页 |
| `Home` `End` | 跳至首/尾 |
| `Space` | 暂停/恢复抓包 |
| `C` | 清除报文列表 |
| `Q` | 退出程序 |

## 架构设计

```
┌─────────────┐
│ pcap 设备    │
│ (libpcap)   │
└──────┬──────┘
       │ pcap_dispatch (批量 1024 包)
       ▼
┌──────────────────────────────────────────┐
│ capture_loop (单线程)                     │
│  ├─ batch_buf → pcap_dump (直接写文件)    │
│  ├─ trylock → pkt_queue (非阻塞推送)      │
│  └─ ui_ring (UI 环形缓冲)                │
└──────┬──────────────┬────────────────────┘
       │              │
       ▼              ▼
┌──────────────┐ ┌──────────────┐
│ parser_worker│ │ parser_worker│  (多线程)
│  解析 TCP/   │ │  解析 UDP/   │
│  UDP/ICMP/   │ │  HTTP/DNS/   │
│  TLS         │ │  TLS         │
└──────┬───────┘ └──────┬───────┘
       │                │
       ▼                ▼
┌──────────────────────────────────────────┐
│ tcp_reassemble (分桶锁 × 256)             │
│  ├─ TCP 流重组 (动态缓冲 8KB→2MB)         │
│  ├─ OOO 乱序缓存 (最多 4 段)              │
│  └─ HTTP 消息提取 + 配对日志              │
└──────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│ traffic_stat (分桶锁 × 256)               │
│  ├─ 五元组流统计                          │
│  ├─ 全局协议分布                          │
│  └─ 定时输出 / UI 面板                    │
└──────────────────────────────────────────┘
```


## 项目结构

```
ZQ/
├── include/            # 头文件
│   ├── common.h        # 公共定义、协议头结构体、数据结构
│   ├── capture.h       # 抓包引擎接口
│   ├── parser.h        # 协议解析接口
│   ├── tcp_reassemble.h# TCP 流重组接口
│   ├── http_parser.h   # HTTP 解析器接口
│   ├── traffic_stat.h  # 流量统计接口
│   ├── ui.h            # UI 接口
│   ├── dns.h           # DNS 解析接口
│   ├── tls_sni.h       # TLS SNI 接口
│   └── logger.h        # 日志接口
├── src/                # 源文件
│   ├── main.c          # 入口、命令行解析
│   ├── capture.c       # 抓包引擎、报文队列
│   ├── parser.c        # 协议解析 (ETH/IP/TCP/UDP/ICMP)
│   ├── tcp_reassemble.c# TCP 流重组、HTTP 配对日志
│   ├── http_parser.c   # HTTP/1.x 解析器
│   ├── traffic_stat.c  # 流量统计
│   ├── ui.c            # ncurses UI
│   ├── dns.c           # DNS 协议解析
│   ├── tls_sni.c       # TLS SNI/ServerHello 解析
│   └── logger.c        # 线程安全日志
├── Makefile            # 构建系统
├── README.md           # 本文档
```

