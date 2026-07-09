#ifndef CAPTURE_H
#define CAPTURE_H
#include <pcap.h>
#include "common.h"

/*
 * open_capture — 打开实时网卡抓包
 *   dev:    网卡名 (如 "eth0", "lo")
 *   filter: BPF 过滤表达式 (可为 NULL)
 *   return: 0 成功, -1 失败
 */
int open_capture(const char *dev, const char *filter);

/*
 * open_pcap_file — 打开离线 pcap 文件回放
 *   file: pcap 文件路径
 *   return: 0 成功, -1 失败
 */
int open_pcap_file(const char *file);

/*
 * save_pcap — 打开写入 pcap 文件
 *   path: 输出 pcap 文件路径
 *   return: 0 成功, -1 失败
 */
int save_pcap(const char *path);

/*
 * close_capture — 关闭抓包句柄和 dumper
 */
void close_capture(void);

/* ── Packet queue (multi-producer / multi-consumer) ── */

void pkt_queue_init(pkt_queue *q, int capacity);
void pkt_queue_destroy(pkt_queue *q);
int  pkt_queue_push(pkt_queue *q, pkt_entry *pkt);
int  pkt_queue_push_batch(pkt_queue *q, pkt_entry *pkts, int count);
int  pkt_queue_pop(pkt_queue *q, pkt_entry *pkt);
void pkt_queue_shutdown(pkt_queue *q);

/* ── UI ring buffer ── */

void ui_ring_init(ui_ring *r, int capacity);
void ui_ring_destroy(ui_ring *r);
void ui_ring_push(ui_ring *r, const struct pcap_pkthdr *hdr, const u_char *data, int len);
int  ui_ring_pop(ui_ring *r, ui_ring_entry *e);

/* ── Thread management ── */

int  capture_thread_start(void);
void capture_thread_stop(void);
int  parser_workers_start(int n, pkt_queue *q);
void parser_workers_stop(void);

/*
 * capture_get_dropped — 获取 pcap 底层丢包统计
 *   dropped:   由驱动丢弃的包数 (ps_drop)
 *   if_dropped: 由接口丢弃的包数 (ps_ifdrop)
 *   return: 0 成功, -1 失败
 */
int capture_get_dropped(unsigned long *dropped, unsigned long *if_dropped);

extern pkt_queue g_pkt_queue;
#endif
