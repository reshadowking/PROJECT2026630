#ifndef TCP_REASSEMBLE_H
#define TCP_REASSEMBLE_H
#include "common.h"

/*
 * tcp_flow_add — 向 TCP 流中添加数据段
 *
 * 基于序列号拼接 TCP 载荷, 支持 OOO (乱序) 重排, 提取完整 HTTP 消息。
 * 使用动态可扩容缓冲区 (初始 8KB, 上限 2MB)。
 *
 *   sip:  IPv4 源地址 (IPv6 时为哈希值)
 *   dip:  IPv4 目标地址 (IPv6 时为哈希值)
 *   sip6: IPv6 源地址 (IPv4 时为 NULL)
 *   dip6: IPv6 目标地址 (IPv4 时为 NULL)
 *   sp:   源端口
 *   dp:   目标端口
 *   seq:  TCP 序列号
 *   pay:  载荷数据指针
 *   len:  载荷长度
 */
void tcp_flow_add(u_int sip, u_int dip,
                  const u_char *sip6, const u_char *dip6,
                  u_short sp, u_short dp,
                  u_uint seq, const u_char *pay, int len);

/*
 * tcp_flow_clear_all — 清空所有 TCP 流 (退出时调用)
 */
void tcp_flow_clear_all(void);

/*
 * tcp_flow_active_count — 返回当前活跃流数量
 */
int tcp_flow_active_count(void);

/*
 * tcp_flow_reap — 回收超时流 (60s 无活动)
 */
void tcp_flow_reap(void);

/*
 * tcp_flow_stats — 获取流统计信息 (供 UI 展示)
 *   buf: 输出缓冲区
 *   len: 缓冲区大小
 */
void tcp_flow_stats(char *buf, size_t len);

/*
 * http_pair_log_init — 初始化 HTTP 配对日志文件
 *   打开 http_pairs.log (追加模式)
 */
void http_pair_log_init(void);

/*
 * http_pair_log_close — 关闭 HTTP 配对日志文件
 */
void http_pair_log_close(void);

#endif
