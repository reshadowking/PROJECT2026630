/*
 * ui.c — ncurses 终端 UI 模块
 *
 * 功能:
 *   1. 实时滚动报文列表 + 协议树展开细节
 *   2. 多标签页: 报文列表 / 流量统计 / 应用层信息 (TAB 切换)
 *   3. 实时丢包率统计面板 (pcap 底层 ps_drop + ps_ifdrop)
 *   4. 协议过滤 (1-6 键: All/TCP/UDP/ICMP/IPv4/IPv6)
 *   5. 交互操作: 方向键滚动、Space 暂停、Q 退出、C 清除
 *
 * 健壮性: initscr() 返回值检查, 终端异常时 fallback 到文本模式
 */

#include "ui.h"
#include "common.h"
#include "capture.h"
#include "traffic_stat.h"
#include <ncurses.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <arpa/inet.h>

#define MAX_UI_PACKETS    100
#define MAX_UI_DETAIL     4096
#define MAX_SUMMARY       128
#define MAX_RAW_BUF       4096
#define MAX_PROTO_TEXT    1024

/* ── UI 标签页 ── */
extern UiTab g_ui_tab;

/* ── 报文协议标签 (用于显示过滤) ── */
typedef enum {
    PKT_OTHER,
    PKT_IPV4_TCP,
    PKT_IPV4_UDP,
    PKT_IPV4_ICMP,
    PKT_IPV6,
} PktProtoTag;

/* ── UI 报文条目 ── */
typedef struct {
    char summary[MAX_SUMMARY];
    char detail[MAX_UI_DETAIL];
    u_char raw[MAX_RAW_BUF];
    unsigned int len;
    struct timeval ts;
    PktProtoTag proto_tag;
} ui_packet;

/* ── ncurses 窗口句柄 ── */
static WINDOW *title_win   = NULL;
static WINDOW *list_win    = NULL;
static WINDOW *detail_win  = NULL;
static WINDOW *stats_win   = NULL;
static WINDOW *tab_bar_win = NULL;

/* ── 报文缓存 ── */
static ui_packet packets[MAX_UI_PACKETS];
static int pkt_count = 0;
static int pkt_selected = 0;
static unsigned long total_packets = 0;
static int detail_scroll = 0;
static int list_scroll = 0;
static int auto_follow = 1;
static pthread_mutex_t ui_mutex = PTHREAD_MUTEX_INITIALIZER;
static char ui_status[128] = "等待报文...";
static time_t ui_start_time;

/* ── 全局变量引用 ── */
extern volatile int exit_flag;
extern volatile int capture_pause;
extern char g_capture_dev[32];
extern char g_capture_filter[256];
extern traffic_stat g_stat;
extern UiFilterType g_ui_filter;
extern char g_filter_hint[64];
int tcp_flow_active_count(void);
void tcp_flow_stats(char *buf, size_t len);

/*
 * human_duration — 格式化运行时长
 */
static void human_duration(char *buf, size_t cap, time_t start)
{
    time_t now = time(NULL);
    int s = (int)(now - start);
    int h = s / 3600; s %= 3600;
    int m = s / 60; s %= 60;
    snprintf(buf, cap, "%02dh%02dm%02ds", h, m, s);
}

/*
 * get_pkt_tag — 获取报文的协议标签 (用于过滤)
 */
static PktProtoTag get_pkt_tag(const u_char *data, uint32_t len)
{
    if (len < 14) return PKT_OTHER;
    struct eth_hdr *eth = (struct eth_hdr *)data;
    uint16_t etype = ntohs(eth->eth_type);
    if (etype == ETH_TYPE_IPV6) return PKT_IPV6;
    if (etype != ETH_TYPE_IPV4) return PKT_OTHER;
    struct ipv4_hdr *ip4 = (struct ipv4_hdr *)(data + sizeof(struct eth_hdr));
    uint8_t proto = ip4->proto;
    if (proto == PROTO_TCP)  return PKT_IPV4_TCP;
    if (proto == PROTO_UDP)  return PKT_IPV4_UDP;
    if (proto == PROTO_ICMP) return PKT_IPV4_ICMP;
    return PKT_OTHER;
}

/*
 * extract_summary — 提取报文摘要行
 */
static void extract_summary(const struct pcap_pkthdr *hdr, const u_char *data,
                             char *out, size_t oc)
{
    out[0] = '\0';
    if (hdr->len <= 14) {
        snprintf(out, oc, "%u ETH", hdr->len);
        return;
    }
    const unsigned char *eth = data;
    uint16_t eth_type = (eth[12] << 8) | eth[13];
    if (eth_type == ETH_TYPE_IPV4 && hdr->len > 34) {
        const unsigned char *ip = data + 14;
        uint8_t ip_ver = (ip[0] >> 4) & 0x0F;
        if (ip_ver == 4) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ip + 12, src, sizeof(src));
            inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));
            uint8_t proto = ip[9];
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            uint16_t sport = (ip[ihl + 14] << 8) | ip[ihl + 15];
            uint16_t dport = (ip[ihl + 16] << 8) | ip[ihl + 17];
            if (proto == PROTO_TCP) {
                snprintf(out, oc, "%u %s:%u->%s:%u TCP", hdr->len, src, sport, dst, dport);
            } else if (proto == PROTO_UDP) {
                snprintf(out, oc, "%u %s:%u->%s:%u UDP", hdr->len, src, sport, dst, dport);
            } else {
                snprintf(out, oc, "%u %s->%s IP%u", hdr->len, src, dst, proto);
            }
        }
    } else if (eth_type == ETH_TYPE_IPV6) {
        /* IPv6 摘要: 显示完整 IPv6 地址 */
        const unsigned char *ip6 = data + 14;
        if (hdr->len > 54) {
            char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ip6 + 8,  src6, sizeof(src6));
            inet_ntop(AF_INET6, ip6 + 24, dst6, sizeof(dst6));
            uint8_t nh = ip6[6];
            snprintf(out, oc, "%u [%s]->[%s] IPv6 nh=%d", hdr->len, src6, dst6, nh);
        } else {
            snprintf(out, oc, "%u IP6", hdr->len);
        }
    } else {
        snprintf(out, oc, "%u ETH 0x%04x", hdr->len, eth_type);
    }
}

/*
 * gen_proto_info — 生成协议树详细信息
 */
void gen_proto_info(char *out, size_t buf_len, const u_char *pkt, uint32_t pkt_len)
{
    memset(out, 0, buf_len);
    char tmp[256];
    uint32_t l2_offset = 0;
    if (pkt_len < sizeof(struct eth_hdr)) return;
    struct eth_hdr *eth = (struct eth_hdr *)pkt;
    uint16_t etype = ntohs(eth->eth_type);
    snprintf(tmp, sizeof(tmp),
        "[二层 以太网]\n"
        "源MAC:%02x:%02x:%02x:%02x:%02x:%02x\n"
        "目MAC:%02x:%02x:%02x:%02x:%02x:%02x\n"
        "以太类型:0x%04X\n",
        eth->src_mac[0],eth->src_mac[1],eth->src_mac[2],
        eth->src_mac[3],eth->src_mac[4],eth->src_mac[5],
        eth->dst_mac[0],eth->dst_mac[1],eth->dst_mac[2],
        eth->dst_mac[3],eth->dst_mac[4],eth->dst_mac[5],
        etype);
    strncat(out, tmp, buf_len - strlen(out) - 1);
    l2_offset += sizeof(struct eth_hdr);

    /* IPv6 */
    if (etype == ETH_TYPE_IPV6 && pkt_len >= l2_offset + sizeof(struct ipv6_hdr)) {
        strncat(out, "[==== 三层 IPv6 头 ====]\n", buf_len - strlen(out) - 1);
        struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(pkt + l2_offset);
        char sip6[INET6_ADDRSTRLEN] = {0};
        char dip6[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, ip6->saddr, sip6, sizeof(sip6));
        inet_ntop(AF_INET6, ip6->daddr, dip6, sizeof(dip6));
        uint16_t pay_len = ntohs(ip6->payload_len);
        snprintf(tmp, sizeof(tmp),
            "源IPv6: %s\n目IPv6: %s\n跳数限制: %d\n"
            "下一头部协议: %d\n载荷长度: %d\n",
            sip6, dip6, ip6->hop_limit, ip6->next_hdr, pay_len);
        strncat(out, tmp, buf_len - strlen(out) - 1);

        uint32_t l4_off = l2_offset + sizeof(struct ipv6_hdr);
        if (pkt_len < l4_off) goto end_hex;

        if (ip6->next_hdr == PROTO_TCP) {
            strncat(out, "[==== 四层 TCP (IPv6) ====]\n", buf_len - strlen(out) - 1);
            struct tcp_hdr *tcp = (struct tcp_hdr *)(pkt + l4_off);
            uint16_t sport = ntohs(tcp->sport);
            uint16_t dport = ntohs(tcp->dport);
            char flags_buf[128] = {0};
            if (tcp->flags & TCP_SYN) strcat(flags_buf, "SYN ");
            if (tcp->flags & TCP_ACK) strcat(flags_buf, "ACK ");
            if (tcp->flags & TCP_FIN) strcat(flags_buf, "FIN ");
            if (tcp->flags & TCP_RST) strcat(flags_buf, "RST ");
            if (tcp->flags & TCP_PSH) strcat(flags_buf, "PSH ");
            snprintf(tmp, sizeof(tmp),
                "源端口: %u | 目端口: %u\n标志: %s\n序号: %u | 确认号: %u\n",
                sport, dport, flags_buf, ntohl(tcp->seq), ntohl(tcp->ack));
            strncat(out, tmp, buf_len - strlen(out) - 1);
        } else if (ip6->next_hdr == PROTO_UDP) {
            strncat(out, "[==== 四层 UDP (IPv6) ====]\n", buf_len - strlen(out) - 1);
            struct udp_hdr *udp = (struct udp_hdr *)(pkt + l4_off);
            uint16_t sport = ntohs(udp->sport);
            uint16_t dport = ntohs(udp->dport);
            snprintf(tmp, sizeof(tmp), "源端口: %u | 目端口: %u\nUDP载荷长度: %u\n",
                sport, dport, ntohs(udp->len));
            strncat(out, tmp, buf_len - strlen(out) - 1);
        }
        goto end_hex;
    }

    /* IPv4 */
    if (etype == ETH_TYPE_IPV4 && pkt_len >= l2_offset + 20) {
        strncat(out, "[==== 三层 IPv4 头 ====]\n", buf_len - strlen(out) - 1);
        struct ipv4_hdr *ip4 = (struct ipv4_hdr *)(pkt + l2_offset);
        char sip4[INET_ADDRSTRLEN] = {0};
        char dip4[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ip4->saddr, sip4, sizeof(sip4));
        inet_ntop(AF_INET, &ip4->daddr, dip4, sizeof(dip4));
        uint8_t ihl = (ip4->ihl & 0x0F) * 4;
        snprintf(tmp, sizeof(tmp),
            "源IP: %s\n目IP: %s\nTTL: %d\n协议: %d\n总长度: %d\n",
            sip4, dip4, ip4->ttl, ip4->proto, ntohs(ip4->total_len));
        strncat(out, tmp, buf_len - strlen(out) - 1);

        uint32_t l4_off = l2_offset + ihl;
        if (ip4->proto == PROTO_TCP && pkt_len >= l4_off + sizeof(struct tcp_hdr)) {
            strncat(out, "[==== 四层 TCP (IPv4) ====]\n", buf_len - strlen(out) - 1);
            struct tcp_hdr *tcp = (struct tcp_hdr *)(pkt + l4_off);
            uint16_t sport = ntohs(tcp->sport);
            uint16_t dport = ntohs(tcp->dport);
            char flags_buf[128] = {0};
            if (tcp->flags & TCP_SYN) strcat(flags_buf, "SYN ");
            if (tcp->flags & TCP_ACK) strcat(flags_buf, "ACK ");
            if (tcp->flags & TCP_FIN) strcat(flags_buf, "FIN ");
            if (tcp->flags & TCP_RST) strcat(flags_buf, "RST ");
            if (tcp->flags & TCP_PSH) strcat(flags_buf, "PSH ");
            snprintf(tmp, sizeof(tmp),
                "源端口: %u | 目端口: %u\n标志: %s\n序号: %u | 确认号: %u\n",
                sport, dport, flags_buf, ntohl(tcp->seq), ntohl(tcp->ack));
            strncat(out, tmp, buf_len - strlen(out) - 1);
        } else if (ip4->proto == PROTO_UDP && pkt_len >= l4_off + sizeof(struct udp_hdr)) {
            strncat(out, "[==== 四层 UDP (IPv4) ====]\n", buf_len - strlen(out) - 1);
            struct udp_hdr *udp = (struct udp_hdr *)(pkt + l4_off);
            uint16_t sport = ntohs(udp->sport);
            uint16_t dport = ntohs(udp->dport);
            snprintf(tmp, sizeof(tmp), "源端口: %u | 目端口: %u\nUDP长度: %u\n",
                sport, dport, ntohs(udp->len));
            strncat(out, tmp, buf_len - strlen(out) - 1);
        }
    }

end_hex:
    strncat(out, "\n==== 原始十六进制 ====\n", buf_len - strlen(out) - 1);
}

/*
 * ui_drain_ring — 从环形缓冲区取出报文加入 UI 列表
 */
void ui_drain_ring(void)
{
    extern ui_ring g_ui_ring;
    ui_ring_entry e;
    int drained = 0;
    while (ui_ring_pop(&g_ui_ring, &e)) {
        ui_add_packet(&e.hdr, e.data);
        drained++;
        if (drained >= 64) break;
    }
}

/* ── 布局函数 ── */
void draw_layout(void)
{
    int h, w;
    getmaxyx(stdscr, h, w);
    int title_h = 3, stats_h = 3, tab_h = 1;
    int body_h = h - title_h - stats_h - tab_h;
    int list_w = w * 60 / 100;
    int detail_w = w - list_w - 1;

    if (!title_win)   title_win   = newwin(title_h, w, 0, 0);
    if (!tab_bar_win) tab_bar_win = newwin(tab_h, w, title_h, 0);
    if (!list_win)    list_win    = newwin(body_h, list_w, title_h + tab_h, 0);
    if (!detail_win)  detail_win  = newwin(body_h, detail_w, title_h + tab_h, list_w + 1);
    if (!stats_win)   stats_win   = newwin(stats_h, w, title_h + tab_h + body_h, 0);

    wbkgd(title_win,   COLOR_PAIR(1));
    wbkgd(tab_bar_win, COLOR_PAIR(1));
    wbkgd(list_win,    COLOR_PAIR(2));
    wbkgd(detail_win,  COLOR_PAIR(2));
    wbkgd(stats_win,   COLOR_PAIR(3));

    werase(title_win);   box(title_win, 0, 0);
    werase(tab_bar_win);
    werase(list_win);    box(list_win, 0, 0);
    werase(detail_win);  box(detail_win, 0, 0);
    werase(stats_win);   box(stats_win, 0, 0);

    /* 标签页栏 */
    const char *tabs[] = { "报文列表", "流量统计", "应用层信息" };
    for (int i = 0; i < 3; i++) {
        if ((int)g_ui_tab == i)
            wattron(tab_bar_win, A_REVERSE);
        mvwprintw(tab_bar_win, 0, 2 + i * 16, " %-13s ", tabs[i]);
        if ((int)g_ui_tab == i)
            wattroff(tab_bar_win, A_REVERSE);
    }
    mvwprintw(tab_bar_win, 0, w - 20, "TAB:切换");

    char dur[64];
    human_duration(dur, sizeof(dur), ui_start_time);
    mvwprintw(title_win, 1, 2, "抓包器 | 网卡:%s 过滤:%s 运行:%s 总数:%lu | %s",
        g_capture_dev, g_capture_filter, dur, total_packets, g_filter_hint);
    mvwprintw(list_win, 1, 2, "#   长度  协议  流信息");

    wrefresh(title_win);
    wrefresh(tab_bar_win);
    wrefresh(list_win);
    wrefresh(detail_win);
    wrefresh(stats_win);
    doupdate();
}

/*
 * ui_init — 初始化 ncurses UI
 *
 * 健壮性: initscr() 失败时 fallback 到文本模式
 */
void ui_init(void)
{
    LOG_INFO("ui_init: initializing ncurses UI");

    /* 设置 locale 启用 UTF-8 中文显示 */
    setlocale(LC_ALL, "");

    WINDOW *scr = initscr();
    if (!scr) {
        LOG_ERROR("ui_init: initscr() returned NULL, falling back to text mode");
        use_ui = 0;
        return;
    }

    cbreak();
    noecho();
    curs_set(0);
    timeout(0);
    keypad(stdscr, 1);

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLUE);
        init_pair(2, COLOR_WHITE, COLOR_BLACK);
        init_pair(3, COLOR_YELLOW, COLOR_BLACK);
        init_pair(4, COLOR_CYAN, COLOR_BLACK);
        init_pair(5, COLOR_GREEN, COLOR_BLACK);
        init_pair(6, COLOR_YELLOW, COLOR_BLACK);
        init_pair(7, COLOR_RED, COLOR_BLACK);
    }

    ui_start_time = time(NULL);
    draw_layout();
    doupdate();
    LOG_INFO("ui_init: ncurses UI initialized OK");
}

/*
 * ui_shutdown — 清理 ncurses UI
 */
void ui_shutdown(void)
{
    LOG_INFO("ui_shutdown: cleaning up UI");
    if (title_win)   { delwin(title_win);   title_win   = NULL; }
    if (tab_bar_win) { delwin(tab_bar_win); tab_bar_win = NULL; }
    if (list_win)    { delwin(list_win);    list_win    = NULL; }
    if (detail_win)  { delwin(detail_win);  detail_win  = NULL; }
    if (stats_win)   { delwin(stats_win);   stats_win   = NULL; }
    endwin();
    LOG_INFO("ui_shutdown: UI cleaned up OK");
}

/*
 * ui_add_packet — 向 UI 缓存添加一个报文
 */
void ui_add_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
    ui_packet p;
    memset(&p, 0, sizeof(p));
    p.len = hdr->len;
    p.ts = hdr->ts;
    p.proto_tag = get_pkt_tag(data, hdr->len);
    extract_summary(hdr, data, p.summary, sizeof(p.summary));

    size_t n = hdr->len > 128 ? 128 : hdr->len;
    char *d = p.detail;
    snprintf(d, MAX_UI_DETAIL, "报文长度: %u\n时间戳: %ld.%06ld\n十六进制:\n",
             hdr->len, (long)p.ts.tv_sec, (long)p.ts.tv_usec);
    size_t off = strlen(d);
    for (size_t i = 0; i < n; i++) {
        char tmp[6];
        snprintf(tmp, sizeof(tmp), "%02x ", data[i]);
        strncpy(d + off, tmp, MAX_UI_DETAIL - off - 1);
        off += 3;
        if ((i + 1) % 16 == 0) {
            d[off++] = '\n';
        }
    }
    size_t copy_len = hdr->len > MAX_RAW_BUF ? MAX_RAW_BUF : hdr->len;
    memcpy(p.raw, data, copy_len);

    pthread_mutex_lock(&ui_mutex);
    if (pkt_count < MAX_UI_PACKETS) {
        packets[pkt_count] = p;
        pkt_count++;
        pkt_selected = pkt_count - 1;
    } else {
        memmove(packets, packets + 1, (MAX_UI_PACKETS - 1) * sizeof(ui_packet));
        packets[MAX_UI_PACKETS - 1] = p;
        pkt_selected = MAX_UI_PACKETS - 1;
    }
    total_packets++;
    pthread_mutex_unlock(&ui_mutex);
}

/* ── 过滤匹配 ── */
static int match_filter(PktProtoTag tag)
{
    switch (g_ui_filter) {
        case UI_FILTER_ALL:  return 1;
        case UI_FILTER_TCP:  return tag == PKT_IPV4_TCP;
        case UI_FILTER_UDP:  return tag == PKT_IPV4_UDP;
        case UI_FILTER_ICMP: return tag == PKT_IPV4_ICMP;
        case UI_FILTER_IPV4:
            return tag == PKT_IPV4_TCP || tag == PKT_IPV4_UDP || tag == PKT_IPV4_ICMP;
        case UI_FILTER_IPV6: return tag == PKT_IPV6;
        default: return 1;
    }
}

static int match_count(void)
{
    int n = 0;
    for (int i = 0; i < pkt_count; i++) {
        if (match_filter(packets[i].proto_tag)) n++;
    }
    return n;
}

static int match_pos(int raw_idx)
{
    int pos = 0;
    for (int i = 0; i < raw_idx && i < pkt_count; i++) {
        if (match_filter(packets[i].proto_tag)) pos++;
    }
    return pos;
}

static int match_idx(int mpos)
{
    int cur = 0;
    for (int i = 0; i < pkt_count; i++) {
        if (match_filter(packets[i].proto_tag)) {
            if (cur == mpos) return i;
            cur++;
        }
    }
    return -1;
}

static int find_prev_match(int from)
{
    for (int i = from - 1; i >= 0; i--) {
        if (match_filter(packets[i].proto_tag)) return i;
    }
    return -1;
}

static int find_next_match(int from)
{
    for (int i = from + 1; i < pkt_count; i++) {
        if (match_filter(packets[i].proto_tag)) return i;
    }
    return -1;
}

/* ──────────────────────────────────────────────
 *  绘制: 流量统计标签页 (Tab 2)
 * ────────────────────────────────────────────── */
static void draw_traffic_stats_tab(int body_h, int list_w, int detail_w)
{
    (void)list_w; (void)detail_w;
    werase(list_win);    box(list_win, 0, 0);
    werase(detail_win);  box(detail_win, 0, 0);

    mvwprintw(list_win, 1, 2, "── 全局统计 ──");

    int row = 2;
    mvwprintw(list_win, row++, 2, "TCP  : %u 包",  g_stat.pkt_tcp);
    mvwprintw(list_win, row++, 2, "UDP  : %u 包",  g_stat.pkt_udp);
    mvwprintw(list_win, row++, 2, "ICMP : %u 包",  g_stat.pkt_icmp);
    mvwprintw(list_win, row++, 2, "HTTP : %u 包",  g_stat.pkt_http);
    mvwprintw(list_win, row++, 2, "DNS  : %u 包",  g_stat.pkt_dns);
    mvwprintw(list_win, row++, 2, "总计 : %u 包, %lu 字节",
              g_stat.pkt_total, g_stat.byte_total);

    row++;
    mvwprintw(list_win, row++, 2, "── 底层丢包 ──");
    unsigned long dropped = 0, if_dropped = 0;
    if (capture_get_dropped(&dropped, &if_dropped) == 0) {
        mvwprintw(list_win, row++, 2, "内核丢包 : %lu", dropped);
        mvwprintw(list_win, row++, 2, "接口丢包 : %lu", if_dropped);
    } else {
        mvwprintw(list_win, row++, 2, "(统计不可用)");
    }

    row++;
    char flow_buf[256];
    tcp_flow_stats(flow_buf, sizeof(flow_buf));
    mvwprintw(list_win, row++, 2, "── TCP 流 ──");
    mvwprintw(list_win, row++, 2, "%s", flow_buf);

    /* 右侧: 实时速率 */
    mvwprintw(detail_win, 1, 2, "── 流表 (前20) ──");
    row = 2;
    extern flow_stat_entry *flow_hash[FLOW_HASH_SIZE];
    /* 快速汇总 TOP-N */
    int shown = 0;
    for (int i = 0; i < FLOW_HASH_SIZE && shown < 20 && row < body_h; i++) {
        flow_stat_entry *e = flow_hash[i];
        while (e && shown < 20 && row < body_h) {
            if (e->pkt_cnt > 0) {
                char src_str[64] = "?", dst_str[64] = "?";
                if (e->key.is_ipv6) {
                    inet_ntop(AF_INET6, e->key.sip6, src_str, sizeof(src_str));
                    inet_ntop(AF_INET6, e->key.dip6, dst_str, sizeof(dst_str));
                } else {
                    struct in_addr sa, da;
                    sa.s_addr = htonl(e->key.sip);
                    da.s_addr = htonl(e->key.dip);
                    strncpy(src_str, inet_ntoa(sa), sizeof(src_str) - 1);
                    strncpy(dst_str, inet_ntoa(da), sizeof(dst_str) - 1);
                }
                mvwprintw(detail_win, row++, 2, "%-22s:%-5u -> %-22s:%-5u p=%d %u/%lu",
                    src_str, e->key.sp, dst_str, e->key.dp,
                    e->key.proto, e->pkt_cnt, e->byte_cnt);
                shown++;
            }
            e = e->next;
        }
    }
}

/* ──────────────────────────────────────────────
 *  绘制: 应用层信息标签页 (Tab 3)
 * ────────────────────────────────────────────── */
static void draw_app_layer_tab(int body_h, int list_w, int detail_w)
{
    (void)list_w; (void)detail_w;
    werase(list_win);    box(list_win, 0, 0);
    werase(detail_win);  box(detail_win, 0, 0);

    mvwprintw(list_win, 1, 2, "── 应用层信息 ──");
    int row = 2;

    mvwprintw(list_win, row++, 2, "HTTP 重组消息 : %u", g_stat.pkt_http);
    mvwprintw(list_win, row++, 2, "DNS 查询检测  : %u", g_stat.pkt_dns);
    mvwprintw(list_win, row++, 2, "TLS 握手检测  : (见调试日志)");

    row++;
    mvwprintw(list_win, row++, 2, "── HTTP 配对日志 ──");
    mvwprintw(list_win, row++, 2, "文件: http_pairs.log");
    mvwprintw(list_win, row++, 2, "请求-响应对以追加模式");
    mvwprintw(list_win, row++, 2, "写入该文件。");

    /* 右侧: 显示最后几个 HTTP 摘要 */
    mvwprintw(detail_win, 1, 2, "── HTTP 活动 ──");
    row = 2;
    for (int i = pkt_count - 1; i >= 0 && row < body_h; i--) {
        if (packets[i].proto_tag == PKT_IPV4_TCP) {
            if (strstr(packets[i].summary, ":80->") || strstr(packets[i].summary, "->80 ")) {
                mvwprintw(detail_win, row++, 2, "%s", packets[i].summary);
            }
        }
    }
}

/*
 * ui_refresh — 刷新整个 UI
 */
void ui_refresh(void)
{
    int h, w;
    getmaxyx(stdscr, h, w);
    int title_h = 3, stats_h = 3, tab_h = 1;
    int body_h = h - title_h - stats_h - tab_h;
    int list_w = w * 60 / 100;
    int detail_w = w - list_w - 1;
    int visible_rows = body_h - 4;
    if (visible_rows < 1) visible_rows = 1;

    /* 重建窗口 (处理终端 resize) */
    if (title_win)   { delwin(title_win);   title_win   = NULL; }
    if (tab_bar_win) { delwin(tab_bar_win); tab_bar_win = NULL; }
    if (list_win)    { delwin(list_win);    list_win    = NULL; }
    if (detail_win)  { delwin(detail_win);  detail_win  = NULL; }
    if (stats_win)   { delwin(stats_win);   stats_win   = NULL; }

    title_win   = newwin(title_h, w, 0, 0);
    tab_bar_win = newwin(tab_h, w, title_h, 0);
    list_win    = newwin(body_h, list_w, title_h + tab_h, 0);
    detail_win  = newwin(body_h, detail_w, title_h + tab_h, list_w + 1);
    stats_win   = newwin(stats_h, w, title_h + tab_h + body_h, 0);

    wbkgd(title_win,   COLOR_PAIR(1));
    wbkgd(tab_bar_win, COLOR_PAIR(1));
    wbkgd(list_win,    COLOR_PAIR(2));
    wbkgd(detail_win,  COLOR_PAIR(2));
    wbkgd(stats_win,   COLOR_PAIR(3));

    werase(title_win);   box(title_win, 0, 0);
    werase(tab_bar_win);
    werase(stats_win);   box(stats_win, 0, 0);

    /* 标签页栏 */
    const char *tabs[] = { "报文列表", "流量统计", "应用层信息" };
    for (int i = 0; i < 3; i++) {
        if ((int)g_ui_tab == i)
            wattron(tab_bar_win, A_REVERSE);
        mvwprintw(tab_bar_win, 0, 2 + i * 16, " %-13s ", tabs[i]);
        if ((int)g_ui_tab == i)
            wattroff(tab_bar_win, A_REVERSE);
    }
    mvwprintw(tab_bar_win, 0, w - 20, "TAB:切换");

    pthread_mutex_lock(&ui_mutex);

    switch (g_ui_tab) {
    case UI_TAB_PACKET_LIST: {
        int total_matched = match_count();

        if (pkt_selected >= pkt_count) pkt_selected = pkt_count > 0 ? pkt_count - 1 : 0;

        if (pkt_count > 0 && !match_filter(packets[pkt_selected].proto_tag)) {
            int nxt = find_next_match(pkt_selected);
            if (nxt >= 0) pkt_selected = nxt;
            else {
                int prv = find_prev_match(pkt_selected);
                pkt_selected = prv >= 0 ? prv : pkt_selected;
            }
        }

        int sel_mpos = match_pos(pkt_selected);

        if (auto_follow && pkt_count > 0 && match_filter(packets[pkt_selected].proto_tag)) {
            list_scroll = sel_mpos - visible_rows + 1;
            if (list_scroll < 0) list_scroll = 0;
        }

        if (sel_mpos < list_scroll) list_scroll = sel_mpos;
        if (sel_mpos >= list_scroll + visible_rows) list_scroll = sel_mpos - visible_rows + 1;
        if (list_scroll < 0) list_scroll = 0;
        if (total_matched > 0 && list_scroll > total_matched - 1)
            list_scroll = (total_matched > visible_rows) ? (total_matched - visible_rows) : 0;

        werase(list_win);   box(list_win, 0, 0);
        werase(detail_win); box(detail_win, 0, 0);

        /* 列表页头部 */
        mvwprintw(list_win, 1, 2, "#   长度  协议  流信息");

        /* 分页提示 */
        if (total_matched > visible_rows) {
            wattron(list_win, COLOR_PAIR(3));
            mvwprintw(list_win, body_h - 2, 2, " [%d-%d/%d]",
                     (int)(list_scroll + 1),
                     (int)(list_scroll + visible_rows < total_matched ? list_scroll + visible_rows : total_matched),
                     (int)total_matched);
            wattroff(list_win, COLOR_PAIR(3));
        }

        int skipped = 0;
        int print_idx = 0;
        for (int i = 0; i < pkt_count && print_idx < visible_rows; i++) {
            if (!match_filter(packets[i].proto_tag)) continue;
            if (skipped < list_scroll) { skipped++; continue; }
            int row = 2 + print_idx;
            if (i == pkt_selected) wattron(list_win, A_REVERSE);
            switch (packets[i].proto_tag) {
                case PKT_IPV4_TCP:  wattron(list_win, COLOR_PAIR(5)); break;
                case PKT_IPV4_UDP:  wattron(list_win, COLOR_PAIR(6)); break;
                case PKT_IPV4_ICMP: wattron(list_win, COLOR_PAIR(7)); break;
                case PKT_IPV6:      wattron(list_win, COLOR_PAIR(4)); break;
                default:            wattron(list_win, COLOR_PAIR(2)); break;
            }
            mvwprintw(list_win, row, 2, "%3d %4u %s", i + 1, packets[i].len, packets[i].summary);
            wattroff(list_win, A_REVERSE);
            wattroff(list_win, COLOR_PAIR(2));
            wattroff(list_win, COLOR_PAIR(4));
            wattroff(list_win, COLOR_PAIR(5));
            wattroff(list_win, COLOR_PAIR(6));
            wattroff(list_win, COLOR_PAIR(7));
            print_idx++;
        }

        /* 协议树细节 */
        if (pkt_count > 0 && pkt_selected < pkt_count && match_filter(packets[pkt_selected].proto_tag)) {
            char proto_buf[MAX_PROTO_TEXT] = {0};
            gen_proto_info(proto_buf, MAX_PROTO_TEXT, packets[pkt_selected].raw, packets[pkt_selected].len);
            int line = 1;
            int ptr = 0;
            while (proto_buf[ptr] != '\0' && line < body_h) {
                char line_buf[256] = {0};
                int idx = 0;
                while (proto_buf[ptr] != '\0' && proto_buf[ptr] != '\n' && idx < detail_w - 2) {
                    line_buf[idx++] = proto_buf[ptr++];
                }
                if (proto_buf[ptr] == '\n') ptr++;
                if (line > detail_scroll) {
                    mvwprintw(detail_win, line - detail_scroll, 2, "%s", line_buf);
                }
                line++;
            }
        }
        break;
    }
    case UI_TAB_TRAFFIC_STATS:
        draw_traffic_stats_tab(body_h, list_w, detail_w);
        break;
    case UI_TAB_APP_LAYER:
        draw_app_layer_tab(body_h, list_w, detail_w);
        break;
    }

    pthread_mutex_unlock(&ui_mutex);

    /* ── 底部状态栏 (所有标签页通用) ── */
    char pause_text[32] = "";
    if (capture_pause) strcpy(pause_text, "[已暂停 - 空格恢复]");

    unsigned long dropped = 0, if_dropped = 0;
    capture_get_dropped(&dropped, &if_dropped);
    mvwprintw(stats_win, 1, 2,
        "TCP:%d UDP:%d ICMP:%d 活跃流:%d | 丢包(内核:%lu 接口:%lu) | 1-6:过滤 TAB:换页 ↑↓ PgUp/PgDn Q:退出 空格:暂停 C:清除 %s",
        g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp,
        tcp_flow_active_count(), dropped, if_dropped, pause_text);

    /* 标题栏 */
    char dur[64];
    human_duration(dur, sizeof(dur), ui_start_time);
    mvwprintw(title_win, 1, 2, "抓包器 | 网卡:%s 过滤:%s 运行:%s 总数:%lu | %s",
        g_capture_dev, g_capture_filter, dur, total_packets, g_filter_hint);

    wrefresh(title_win);
    wrefresh(tab_bar_win);
    wrefresh(list_win);
    wrefresh(detail_win);
    wrefresh(stats_win);
    doupdate();
}

/*
 * ui_set_status — 设置状态栏文本
 */
void ui_set_status(const char *status)
{
    pthread_mutex_lock(&ui_mutex);
    strncpy(ui_status, status, sizeof(ui_status) - 1);
    ui_status[sizeof(ui_status) - 1] = '\0';
    pthread_mutex_unlock(&ui_mutex);
}

/*
 * ui_get_total_packets — 获取总报文数
 */
unsigned long ui_get_total_packets(void)
{
    pthread_mutex_lock(&ui_mutex);
    unsigned long n = total_packets;
    pthread_mutex_unlock(&ui_mutex);
    return n;
}

/*
 * ui_handle_input — 处理键盘输入
 *   return: 1 有变更需要刷新, 0 无变更
 */
int ui_handle_input(void)
{
    int ch = getch();
    if (ch == ERR) return 0;

    /* ── 全局按键 (所有标签页通用) ── */
    if (ch == 9) {  /* TAB */
        g_ui_tab = (UiTab)(((int)g_ui_tab + 1) % 3);
        return 1;
    }
    if (ch == 'q' || ch == 'Q') {
        exit_flag = 1;
        LOG_INFO("exit requested by user (Q)");
        return 0;
    }
    if (ch == ' ') {
        capture_pause = !capture_pause;
        if (capture_pause) {
            ui_set_status("已暂停 - 按空格恢复");
            LOG_INFO("capture paused by user");
        } else {
            ui_set_status("正在抓包");
            LOG_INFO("capture resumed by user");
        }
        return 1;
    }
    if (ch == 'c' || ch == 'C') {
        pthread_mutex_lock(&ui_mutex);
        pkt_count = 0;
        pkt_selected = 0;
        total_packets = 0;
        detail_scroll = 0;
        list_scroll = 0;
        auto_follow = 1;
        memset(packets, 0, sizeof(packets));
        pthread_mutex_unlock(&ui_mutex);
        return 1;
    }

    /* ── 过滤按键 (仅报文列表页) ── */
    if (ch == '1') { g_ui_filter = UI_FILTER_ALL;  strcpy(g_filter_hint, "过滤: 全部");  list_scroll = 0; auto_follow = 0; return 1; }
    if (ch == '2') { g_ui_filter = UI_FILTER_TCP;  strcpy(g_filter_hint, "过滤: 仅TCP");  list_scroll = 0; auto_follow = 0; return 1; }
    if (ch == '3') { g_ui_filter = UI_FILTER_UDP;  strcpy(g_filter_hint, "过滤: 仅UDP");  list_scroll = 0; auto_follow = 0; return 1; }
    if (ch == '4') { g_ui_filter = UI_FILTER_ICMP; strcpy(g_filter_hint, "过滤: 仅ICMP"); list_scroll = 0; auto_follow = 0; return 1; }
    if (ch == '5') { g_ui_filter = UI_FILTER_IPV4; strcpy(g_filter_hint, "过滤: 仅IPv4"); list_scroll = 0; auto_follow = 0; return 1; }
    if (ch == '6') { g_ui_filter = UI_FILTER_IPV6; strcpy(g_filter_hint, "过滤: 仅IPv6"); list_scroll = 0; auto_follow = 0; return 1; }

    /* ── 报文列表页导航 ── */
    if (g_ui_tab != UI_TAB_PACKET_LIST) return 0;
    if (pkt_count == 0) return 0;

    pthread_mutex_lock(&ui_mutex);

    int h, w;
    getmaxyx(stdscr, h, w);
    (void)w;
    int body_h = h - 7;  /* title(3) + tab(1) + stats(3) */
    int visible_rows = body_h - 4;
    if (visible_rows < 1) visible_rows = 1;

    int changed = 0;
    if (ch == KEY_UP) {
        auto_follow = 0;
        int prv = find_prev_match(pkt_selected);
        if (prv >= 0) { pkt_selected = prv; changed = 1; }
    } else if (ch == KEY_DOWN) {
        auto_follow = 0;
        int nxt = find_next_match(pkt_selected);
        if (nxt >= 0) { pkt_selected = nxt; changed = 1; }
    } else if (ch == KEY_NPAGE) {
        auto_follow = 0;
        list_scroll += visible_rows;
        int raw = match_idx(list_scroll);
        if (raw < 0) {
            int mc = match_count();
            if (mc > 0) {
                int last_mpos = mc - 1;
                raw = match_idx(last_mpos);
                if (raw >= 0) {
                    pkt_selected = raw;
                    list_scroll = (mc > visible_rows) ? (mc - visible_rows) : 0;
                    changed = 1;
                }
            } else {
                list_scroll -= visible_rows;
            }
        } else {
            pkt_selected = raw;
            changed = 1;
        }
    } else if (ch == KEY_PPAGE) {
        auto_follow = 0;
        list_scroll -= visible_rows;
        if (list_scroll < 0) list_scroll = 0;
        int raw = match_idx(list_scroll);
        if (raw >= 0) { pkt_selected = raw; changed = 1; }
    } else if (ch == KEY_HOME) {
        auto_follow = 0;
        list_scroll = 0;
        int raw = match_idx(0);
        if (raw >= 0) { pkt_selected = raw; changed = 1; }
    } else if (ch == KEY_END) {
        auto_follow = 0;
        int mc = match_count();
        if (mc > 0) {
            int last_mpos = mc - 1;
            int raw = match_idx(last_mpos);
            if (raw >= 0) {
                pkt_selected = raw;
                list_scroll = (mc > visible_rows) ? (mc - visible_rows) : 0;
                changed = 1;
            }
        }
    }

    pthread_mutex_unlock(&ui_mutex);
    return changed;
}
