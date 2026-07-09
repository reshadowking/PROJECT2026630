#ifndef SRC_UI_H
#define SRC_UI_H

#include <pcap.h>
#include "common.h"

/*
 * ui_init — 初始化 ncurses UI
 *
 * initscr() 失败时自动 fallback 到文本模式 (use_ui = 0)
 */
void ui_init(void);

/*
 * ui_shutdown — 清理并关闭 ncurses UI
 */
void ui_shutdown(void);

/*
 * ui_refresh — 刷新整个 UI (所有标签页)
 */
void ui_refresh(void);

/*
 * ui_handle_input — 处理键盘输入
 *   return: 1 有变更需刷新, 0 无变更
 */
int ui_handle_input(void);

/*
 * ui_add_packet — 向 UI 缓存添加一个报文
 */
void ui_add_packet(const struct pcap_pkthdr *hdr, const u_char *data);

/*
 * ui_drain_ring — 从 UI 环形缓冲区取出报文加入缓存
 */
void ui_drain_ring(void);

/*
 * ui_set_status — 设置底部状态栏文本
 */
void ui_set_status(const char *status);

/*
 * draw_layout — 初始化绘制窗口布局 (已废弃, 由 ui_refresh 内部处理)
 */
void draw_layout(void);

/*
 * gen_proto_info — 生成协议树详细信息字符串
 *   out:     输出缓冲区
 *   buf_len: 缓冲区大小
 *   pkt:     原始报文数据
 *   pkt_len: 报文长度
 */
void gen_proto_info(char *out, size_t buf_len, const u_char *pkt, uint32_t pkt_len);

/*
 * ui_get_total_packets — 获取 UI 已处理的报文总数
 */
unsigned long ui_get_total_packets(void);

#endif
