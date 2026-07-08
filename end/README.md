PROJECT2026630/
├── src/                 # 核心业务实现源码（.c文件，可修改迭代）
│   ├── main.c           程序入口、命令行解析、生命周期调度、信号处理
│   ├── capture.c        libpcap底层封装、网卡抓包、PCAP读写、BPF过滤器实现
│   ├── parser.c         多层网络协议分层解析核心逻辑
│   ├── traffic_stat.c   独立子线程实时流量统计模块
│   ├── tcp_reassemble.c TCP分片报文重组、HTTP完整报文拼接
│   └── tls_sni.c       TLS握手解析、HTTPS域名SNI提取
├── include/             # 公共头文件目录（.h文件，统一接口，只读少改）
│   ├── common.h         全局协议结构体、公共宏定义、全局变量声明
│   ├── capture.h       抓包模块对外接口声明
│   ├── parser.h        协议解析模块接口声明
│   ├── traffic_stat.h  流量统计模块接口声明
│   ├── tcp_reassemble.h TCP重组模块接口声明
│   └── tls_sni.h       TLS解析模块接口声明
├── Makefile             一键自动化编译脚本
├── README.md            项目说明文档
└── .gitignore           仓库忽略配置（过滤编译产物、缓存、抓包文件）