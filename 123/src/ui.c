#include "ui.h"
#include "common.h"
#include "parser.h"
#include "traffic_stat.h"
#include <ncurses.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#define MAX_UI_PACKETS 200
#define MAX_UI_DETAIL  4096
#define MAX_SUMMARY    128
#define MAX_RAW_BUF    4096
#define MAX_PROTO_TEXT 1024

/* ── View tabs (right panel) ── */
typedef enum {
    VIEW_PACKETS,   /* protocol details of selected packet */
    VIEW_TRAFFIC,   /* top-N flow ranking              */
    VIEW_APPINFO,   /* DNS / TLS / HTTP info           */
    VIEW_COUNT
} UiViewType;

/* ── Packet protocol tag (left list filtering) ── */
typedef enum {
    PKT_OTHER,
    PKT_IPV4_TCP,
    PKT_IPV4_UDP,
    PKT_IPV4_ICMP,
    PKT_IPV6,
} PktProtoTag;

/* ── Extended packet record ── */
typedef struct {
    char summary[MAX_SUMMARY];
    char detail[MAX_UI_DETAIL];
    u_char raw[MAX_RAW_BUF];
    unsigned int len;
    struct timeval ts;
    PktProtoTag proto_tag;
    char dns_domain[256];      /* DNS query name                  */
    char tls_sni[256];         /* TLS SNI host name               */
    char http_method[16];      /* HTTP method (GET/POST/…)        */
} ui_packet;

/* ── Globals ── */
static WINDOW *title_win  = NULL;
static WINDOW *list_win   = NULL;
static WINDOW *detail_win = NULL;
static WINDOW *stats_win  = NULL;

static ui_packet packets[MAX_UI_PACKETS];
static int pkt_count       = 0;
static int pkt_selected    = 0;
static int list_scroll     = 0;      /* left-list scroll offset       */
static int detail_scroll   = 0;      /* right-panel scroll offset     */
static unsigned long total_packets = 0;

static UiViewType g_current_view = VIEW_PACKETS;
static pthread_mutex_t ui_mutex = PTHREAD_MUTEX_INITIALIZER;
static char ui_status[128] = "Waiting for packets...";
static time_t ui_start_time;

/* External symbols */
extern volatile int exit_flag;
extern volatile int capture_pause;
extern char g_capture_dev[32];
extern char g_capture_filter[256];
extern traffic_stat g_stat;
extern UiFilterType g_ui_filter;
extern char g_filter_hint[64];

int tcp_flow_active_count(void);

/* ── Helpers ── */
static void human_duration(char *buf, size_t cap, time_t start)
{
    time_t now = time(NULL);
    int s = (int)(now - start);
    int h = s / 3600; s %= 3600;
    int m = s / 60;   s %= 60;
    snprintf(buf, cap, "%02dh%02dm%02ds", h, m, s);
}

static PktProtoTag get_pkt_tag(const u_char *data, uint32_t len)
{
    if (len < 14) return PKT_OTHER;
    struct eth_hdr *eth = (struct eth_hdr *)data;
    uint16_t etype = ntohs(eth->eth_type);
    if (etype == ETH_TYPE_IPV6) return PKT_IPV6;
    if (etype != ETH_TYPE_IPV4) return PKT_OTHER;
    struct ipv4_hdr *ip4 = (struct ipv4_hdr *)(data + sizeof(struct eth_hdr));
    uint8_t proto = ip4->proto;
    if (proto == PROTO_TCP)   return PKT_IPV4_TCP;
    if (proto == PROTO_UDP)   return PKT_IPV4_UDP;
    if (proto == PROTO_ICMP)  return PKT_IPV4_ICMP;
    return PKT_OTHER;
}

/* Extract a one-line summary for the left list */
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

            if (proto == 6 && hdr->len > (14 + ihl + 20)) {
                uint16_t sport = (ip[ihl + 14] << 8) | ip[ihl + 15];
                uint16_t dport = (ip[ihl + 16] << 8) | ip[ihl + 17];
                snprintf(out, oc, "%u %s:%u->%s:%u TCP",
                         hdr->len, src, sport, dst, dport);
            } else if (proto == 17) {
                uint16_t sport = (ip[ihl + 14] << 8) | ip[ihl + 15];
                uint16_t dport = (ip[ihl + 16] << 8) | ip[ihl + 17];
                snprintf(out, oc, "%u %s:%u->%s:%u UDP",
                         hdr->len, src, sport, dst, dport);
            } else {
                snprintf(out, oc, "%u %s->%s IP%u",
                         hdr->len, src, dst, proto);
            }
        }
    } else if (eth_type == ETH_TYPE_IPV6) {
        snprintf(out, oc, "%u IP6", hdr->len);
    } else {
        snprintf(out, oc, "%u ETH 0x%04x", hdr->len, eth_type);
    }
}

/* ── Protocol detail text ── */
void gen_proto_info(char *out, size_t buf_len, const u_char *pkt, uint32_t pkt_len)
{
    memset(out, 0, buf_len);
    char tmp[256];
    uint32_t offset = 0;

    if (pkt_len < sizeof(struct eth_hdr)) return;

    struct eth_hdr *eth = (struct eth_hdr *)pkt;
    uint16_t etype = ntohs(eth->eth_type);
    snprintf(tmp, sizeof(tmp),
        "[Layer 2 Ethernet]\n"
        "Src MAC:%02x:%02x:%02x:%02x:%02x:%02x\n"
        "Dst MAC:%02x:%02x:%02x:%02x:%02x:%02x\n"
        "Type:0x%04X\n",
        eth->src_mac[0],eth->src_mac[1],eth->src_mac[2],
        eth->src_mac[3],eth->src_mac[4],eth->src_mac[5],
        eth->dst_mac[0],eth->dst_mac[1],eth->dst_mac[2],
        eth->dst_mac[3],eth->dst_mac[4],eth->dst_mac[5],
        etype);
    strncat(out, tmp, buf_len - strlen(out) - 1);
    offset += sizeof(struct eth_hdr);

    if (etype == ETH_TYPE_IPV4 && pkt_len >= offset + 20) {
        strncat(out, "[Layer 3 IPv4]\n", buf_len - strlen(out) - 1);
        struct ipv4_hdr *ip4 = (struct ipv4_hdr *)(pkt + offset);
        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip4->saddr, sip, sizeof(sip));
        inet_ntop(AF_INET, &ip4->daddr, dip, sizeof(dip));
        snprintf(tmp, sizeof(tmp), "Src IP:%s\nDst IP:%s\nTTL:%d Proto:%d\n",
                 sip, dip, ip4->ttl, ip4->proto);
        strncat(out, tmp, buf_len - strlen(out) - 1);
        int ihl = (ip4->ihl & 0x0F) * 4;
        offset += ihl;

        if (ip4->proto == PROTO_TCP && pkt_len >= offset + 20) {
            strncat(out, "[Layer 4 TCP]\n", buf_len - strlen(out) - 1);
            struct tcp_hdr *tcp = (struct tcp_hdr *)(pkt + offset);
            uint16_t sp = ntohs(tcp->sport), dp = ntohs(tcp->dport);
            char flag_str[64] = "";
            if (tcp->flags & TCP_SYN) strcat(flag_str, "SYN ");
            if (tcp->flags & TCP_ACK) strcat(flag_str, "ACK ");
            if (tcp->flags & TCP_FIN) strcat(flag_str, "FIN ");
            if (tcp->flags & TCP_RST) strcat(flag_str, "RST ");
            if (tcp->flags & TCP_PSH) strcat(flag_str, "PSH ");
            snprintf(tmp, sizeof(tmp),
                     "Src Port:%d Dst Port:%d Flags:%s Seq:%u Ack:%u\n",
                     sp, dp, flag_str, ntohl(tcp->seq), ntohl(tcp->ack));
            strncat(out, tmp, buf_len - strlen(out) - 1);
        } else if (ip4->proto == PROTO_UDP && pkt_len >= offset + 8) {
            strncat(out, "[Layer 4 UDP]\n", buf_len - strlen(out) - 1);
            struct udp_hdr *udp = (struct udp_hdr *)(pkt + offset);
            snprintf(tmp, sizeof(tmp),
                     "Src Port:%d Dst Port:%d\n",
                     ntohs(udp->sport), ntohs(udp->dport));
            strncat(out, tmp, buf_len - strlen(out) - 1);
        }
    } else if (etype == ETH_TYPE_IPV6 && pkt_len >= offset + 40) {
        strncat(out, "[Layer 3 IPv6]\n", buf_len - strlen(out) - 1);
        struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(pkt + offset);
        char sip6[INET6_ADDRSTRLEN], dip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip6->saddr, sip6, sizeof(sip6));
        inet_ntop(AF_INET6, ip6->daddr, dip6, sizeof(dip6));
        snprintf(tmp, sizeof(tmp),
                 "Src IP:%s\nDst IP:%s\nHop Limit:%d NextHdr:%d\n",
                 sip6, dip6, ip6->hop_limit, ip6->next_hdr);
        strncat(out, tmp, buf_len - strlen(out) - 1);
    }
    strncat(out, "==== Raw Hex Dump ====\n", buf_len - strlen(out) - 1);
}

/* ── Filter matching ── */
static int match_filter(PktProtoTag tag)
{
    switch (g_ui_filter) {
        case UI_FILTER_ALL:     return 1;
        case UI_FILTER_TCP:     return tag == PKT_IPV4_TCP;
        case UI_FILTER_UDP:     return tag == PKT_IPV4_UDP;
        case UI_FILTER_ICMP:    return tag == PKT_IPV4_ICMP;
        case UI_FILTER_IPV4:    return tag == PKT_IPV4_TCP || tag == PKT_IPV4_UDP || tag == PKT_IPV4_ICMP;
        case UI_FILTER_IPV6:    return tag == PKT_IPV6;
        default:                return 1;
    }
}

/* Count how many packets match the current filter (for visible range calc) */
static int count_filtered(void)
{
    int n = 0;
    for (int i = 0; i < pkt_count; i++) {
        if (match_filter(packets[i].proto_tag)) n++;
    }
    return n;
}

/* ── Layout helpers ── */
static void calc_layout(int *h, int *w, int *body_h, int *list_w, int *detail_w)
{
    /* Defend against uninitialized stdscr (e.g. initscr() failed) */
    if (!stdscr) {
        *h = 24; *w = 80;
    } else {
        getmaxyx(stdscr, *h, *w);
    }
    /* Clamp to sane minimums so newwin() won't reject the geometry */
    if (*h < 10) *h = 24;
    if (*w  < 30) *w  = 80;

    int title_h = 3, stats_h = 3;
    *body_h = *h - title_h - stats_h;
    if (*body_h < 1) *body_h = 1;

    *list_w   = (*w * 60) / 100;
    *detail_w = *w - *list_w - 1;
    if (*list_w   < 5) *list_w   = 5;
    if (*detail_w < 5) *detail_w = 5;
}

/* ── Window creation / resize ── */
void draw_layout(void)
{
    int h, w, body_h, list_w, detail_w;
    calc_layout(&h, &w, &body_h, &list_w, &detail_w);

    if (!title_win)  title_win  = newwin(3, w, 0, 0);
    if (!list_win)   list_win   = newwin(body_h, list_w, 3, 0);
    if (!detail_win) detail_win = newwin(body_h, detail_w, 3, list_w + 1);
    if (!stats_win)  stats_win  = newwin(3, w, h - 3, 0);

    /* Guard every call: newwin() may have returned NULL on bad geometry */
    if (title_win) { werase(title_win);  box(title_win, 0, 0); }
    if (list_win)  { werase(list_win);   box(list_win, 0, 0); }
    if (detail_win){ werase(detail_win); box(detail_win, 0, 0); }
    if (stats_win) { werase(stats_win);  box(stats_win, 0, 0); }

    /* Title bar content */
    if (title_win) {
        mvwprintw(title_win, 1, 2, "[ Network Packet Sniffer ]");
    }

    if (title_win)  wrefresh(title_win);
    if (list_win)   wrefresh(list_win);
    if (detail_win) wrefresh(detail_win);
    if (stats_win)  wrefresh(stats_win);
    doupdate();
}

void ui_init(void)
{
    if (!initscr()) {
        fprintf(stderr, "Failed to initialize ncurses (is TERM set?)\n");
        exit(1);
    }
    cbreak(); noecho(); curs_set(0); timeout(10); keypad(stdscr, 1);
    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLUE);
        init_pair(2, COLOR_WHITE, COLOR_BLACK);
        init_pair(3, COLOR_YELLOW, COLOR_BLACK);
        init_pair(4, COLOR_CYAN, COLOR_BLACK);
        init_pair(5, COLOR_GREEN, COLOR_BLACK);
        init_pair(6, COLOR_MAGENTA, COLOR_BLACK);
    }
    ui_start_time = time(NULL);
    draw_layout();
    doupdate();
}

void ui_shutdown(void)
{
    if (title_win)  { delwin(title_win);  title_win  = NULL; }
    if (list_win)   { delwin(list_win);   list_win   = NULL; }
    if (detail_win) { delwin(detail_win); detail_win = NULL; }
    if (stats_win)  { delwin(stats_win);  stats_win  = NULL; }
    endwin();
}

/* ── Add a captured packet: parse layers + store application-layer info ── */
void ui_add_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
    ui_packet p = {0};
    p.len    = hdr->len;
    p.ts     = hdr->ts;
    p.proto_tag = get_pkt_tag(data, hdr->len);

    extract_summary(hdr, data, p.summary, sizeof(p.summary));

    /* Run protocol parsers to fill in DNS / TLS / HTTP fields */
    if (hdr->len >= 14) {
        const u_char *ip_start = data + sizeof(struct eth_hdr);
        int ip_len = (int)hdr->len - (int)sizeof(struct eth_hdr);
        if (ip_len >= (int)sizeof(struct ipv4_hdr)) {
            struct ipv4_hdr *ip4 = (struct ipv4_hdr *)ip_start;
            uint8_t ihl_bytes = (ip4->ihl & 0x0F) * 4;
            if (ip4->proto == PROTO_TCP && ip_len >= (int)ihl_bytes + (int)sizeof(struct tcp_hdr)) {
                parse_tcp(ip_start + ihl_bytes, ip_len - ihl_bytes,
                          ntohl(ip4->saddr), ntohl(ip4->daddr),
                          p.tls_sni, sizeof(p.tls_sni),
                          p.http_method, sizeof(p.http_method));
            } else if (ip4->proto == PROTO_UDP && ip_len >= (int)ihl_bytes + (int)sizeof(struct udp_hdr)) {
                parse_udp(ip_start + ihl_bytes, ip_len - ihl_bytes,
                          ntohl(ip4->saddr), ntohl(ip4->daddr),
                          p.dns_domain, sizeof(p.dns_domain));
            }
        }
    }

    /* Detail text (hex dump) */
    size_t n = hdr->len > 128 ? 128 : hdr->len;
    char d[MAX_UI_DETAIL];
    snprintf(d, sizeof(d), "Packet Length: %u\nTimestamp: %ld.%06ld\nHex Dump:\n",
             hdr->len, p.ts.tv_sec, p.ts.tv_usec);
    size_t off = strlen(d);
    memcpy(p.detail, d, sizeof(p.detail));
    off = strlen(p.detail);
    for (size_t i = 0; i < n; i++) {
        char tmp[6];
        snprintf(tmp, sizeof(tmp), "%02x ", data[i]);
        size_t remain = sizeof(p.detail) - off - 1;
        if (remain == 0) break;
        strncat(p.detail + off, tmp, remain);
        off += 3;
        if ((i + 1) % 16 == 0 && off < sizeof(p.detail) - 1)
            p.detail[off++] = '\n';
    }

    /* Raw buffer */
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

/* ── Application-layer query APIs ── */
int ui_get_dns_domains(char domains[][256], int max_n)
{
    pthread_mutex_lock(&ui_mutex);
    int count = 0;
    for (int i = 0; i < pkt_count && count < max_n; i++) {
        if (packets[i].dns_domain[0] != '\0') {
            /* Deduplicate */
            int dup = 0;
            for (int j = 0; j < count; j++) {
                if (strcmp(domains[j], packets[i].dns_domain) == 0) {
                    dup = 1; break;
                }
            }
            if (!dup) {
                strncpy(domains[count], packets[i].dns_domain, 255);
                domains[count][255] = '\0';
                count++;
            }
        }
    }
    pthread_mutex_unlock(&ui_mutex);
    return count;
}

int ui_get_tls_snis(char snis[][256], int max_n)
{
    pthread_mutex_lock(&ui_mutex);
    int count = 0;
    for (int i = 0; i < pkt_count && count < max_n; i++) {
        if (packets[i].tls_sni[0] != '\0') {
            int dup = 0;
            for (int j = 0; j < count; j++) {
                if (strcmp(snis[j], packets[i].tls_sni) == 0) {
                    dup = 1; break;
                }
            }
            if (!dup) {
                strncpy(snis[count], packets[i].tls_sni, 255);
                snis[count][255] = '\0';
                count++;
            }
        }
    }
    pthread_mutex_unlock(&ui_mutex);
    return count;
}

/* ── Refresh: left list + right panel ── */
void ui_refresh(void)
{
    int h, w, body_h, list_w, detail_w;
    calc_layout(&h, &w, &body_h, &list_w, &detail_w);

    /* Only recreate windows when terminal size actually changes */
    static int last_h = 0, last_w = 0;
    static int resize_skip = 0;

    /* Check resize only every 10 refreshes to reduce overhead */
    resize_skip = (resize_skip + 1) % 10;
    if (resize_skip == 0) {
        if (last_h != h || last_w != w) {
            if (title_win)  { delwin(title_win);  title_win  = NULL; }
            if (list_win)   { delwin(list_win);   list_win   = NULL; }
            if (detail_win) { delwin(detail_win); detail_win = NULL; }
            if (stats_win)  { delwin(stats_win);  stats_win  = NULL; }
            draw_layout();
            last_h = h;
            last_w = w;
            /* After resize, return early — data will be drawn next refresh */
            return;
        }
    }

    /* Clear the content windows (only if they exist) */
    if (list_win)  { werase(list_win);  box(list_win, 0, 0); }
    if (detail_win){ werase(detail_win); box(detail_win, 0, 0); }
    if (stats_win) { werase(stats_win);  box(stats_win, 0, 0); }

    int visible_rows = body_h - 2;

    /* ── Left panel: packet list ── */
    pthread_mutex_lock(&ui_mutex);

    /* Clamp pkt_selected into valid range */
    if (pkt_count > 0) {
        if (pkt_selected < 0) pkt_selected = 0;
        if (pkt_selected >= pkt_count) pkt_selected = pkt_count - 1;
    }

    /* Auto-scroll: keep selected packet visible */
    int total_filtered = count_filtered();
    if (total_filtered > visible_rows && visible_rows > 0) {
        /* Find the visual row of pkt_selected */
        int vis_of_selected = 0;
        for (int i = 0; i < pkt_selected && i < pkt_count; i++) {
            if (match_filter(packets[i].proto_tag)) vis_of_selected++;
        }
        if (vis_of_selected < list_scroll)
            list_scroll = vis_of_selected;
        if (vis_of_selected >= list_scroll + visible_rows)
            list_scroll = vis_of_selected - visible_rows + 1;
    } else {
        list_scroll = 0;
    }
    /* Clamp list_scroll */
    if (list_scroll < 0) list_scroll = 0;
    if (total_filtered > 0 && list_scroll > total_filtered - 1)
        list_scroll = total_filtered - 1;
    if (total_filtered == 0) list_scroll = 0;

    /* Draw visible range */
    int drawn = 0;           /* how many filtered packets we've passed */
    int visible_drawn = 0;   /* how many we've actually drawn on screen */

    for (int i = 0; i < pkt_count && visible_drawn < visible_rows; i++) {
        if (!match_filter(packets[i].proto_tag)) continue;

        /* Skip packets before the scroll offset */
        if (drawn < list_scroll) { drawn++; continue; }

        int row = 1 + visible_drawn;
        if (row >= body_h) break;

        if (i == pkt_selected)
            wattron(list_win, A_REVERSE);

        /* Color by protocol */
        if (strstr(packets[i].summary, "TCP"))
            wattron(list_win, COLOR_PAIR(2));
        else if (strstr(packets[i].summary, "UDP"))
            wattron(list_win, COLOR_PAIR(5));
        else if (strstr(packets[i].summary, "IP6"))
            wattron(list_win, COLOR_PAIR(4));
        else
            wattron(list_win, COLOR_PAIR(1));

        /* Build list label */
        char label[MAX_SUMMARY + 64] = {0};
        int p = 0;
        p += snprintf(label + p, sizeof(label) - p, "%3d ", i + 1);
        if (packets[i].dns_domain[0] != '\0')
            p += snprintf(label + p, sizeof(label) - p, "DNS:%s ", packets[i].dns_domain);
        if (packets[i].tls_sni[0] != '\0')
            p += snprintf(label + p, sizeof(label) - p, "SNI:%s ", packets[i].tls_sni);
        if (packets[i].http_method[0] != '\0')
            p += snprintf(label + p, sizeof(label) - p, "%s ", packets[i].http_method);

        mvwprintw(list_win, row, 1, "%s%s", label, packets[i].summary);

        wattroff(list_win, A_REVERSE);
        wattroff(list_win, COLOR_PAIR(4));
        wattroff(list_win, COLOR_PAIR(5));
        wattroff(list_win, COLOR_PAIR(2));
        wattroff(list_win, COLOR_PAIR(1));

        drawn++;
        visible_drawn++;
    }

    /* ── Right panel: current view ── */
    if (pkt_count > 0 && pkt_selected >= 0 && pkt_selected < pkt_count) {
        int sel_idx = pkt_selected;

        switch (g_current_view) {
        case VIEW_PACKETS:
            /* Protocol details */
            {
                char proto_buf[MAX_PROTO_TEXT] = {0};
                gen_proto_info(proto_buf, MAX_PROTO_TEXT,
                               packets[sel_idx].raw, packets[sel_idx].len);

                /* Append application-layer info */
                if (packets[sel_idx].dns_domain[0] != '\0') {
                    char app[300];
                    snprintf(app, sizeof(app), "\n[DNS] Query: %.250s\n", packets[sel_idx].dns_domain);
                    strncat(proto_buf, app, sizeof(proto_buf) - strlen(proto_buf) - 1);
                }
                if (packets[sel_idx].tls_sni[0] != '\0') {
                    char app[300];
                    snprintf(app, sizeof(app), "[TLS] SNI: %.250s\n", packets[sel_idx].tls_sni);
                    strncat(proto_buf, app, sizeof(proto_buf) - strlen(proto_buf) - 1);
                }
                if (packets[sel_idx].http_method[0] != '\0') {
                    char app[64];
                    snprintf(app, sizeof(app), "[HTTP] Method: %s\n", packets[sel_idx].http_method);
                    strncat(proto_buf, app, sizeof(proto_buf) - strlen(proto_buf) - 1);
                }

                int line = 1;
                int ptr  = 0;
                while (proto_buf[ptr] != '\0' && line < body_h) {
                    char line_buf[256] = {0};
                    int idx = 0;
                    while (proto_buf[ptr] != '\0' && proto_buf[ptr] != '\n' && idx < detail_w - 3)
                        line_buf[idx++] = proto_buf[ptr++];
                    if (proto_buf[ptr] == '\n') ptr++;
                    if (line > detail_scroll) {
                        mvwprintw(detail_win, line - detail_scroll, 1, "%s", line_buf);
                    }
                    line++;
                }
            }
            break;

        case VIEW_TRAFFIC:
            mvwprintw(detail_win, 1, 1, "=== Top Flows by Bytes ===");
            pthread_mutex_lock(&flow_hash_mutex);
            int nflows = 0;
            flow_stat_entry sorted[FLOW_HASH_SIZE];
            for (int i = 0; i < FLOW_HASH_SIZE; i++) {
                if (flow_hash[i].pkt_cnt > 0) {
                    sorted[nflows++] = flow_hash[i];
                }
            }
            /* Selection sort descending by byte_cnt */
            for (int i = 0; i < nflows - 1 && i < 20; i++) {
                int max_idx = i;
                for (int j = i + 1; j < nflows; j++) {
                    if (sorted[j].byte_cnt > sorted[max_idx].byte_cnt)
                        max_idx = j;
                }
                if (max_idx != i) {
                    flow_stat_entry tmp = sorted[i];
                    sorted[i] = sorted[max_idx];
                    sorted[max_idx] = tmp;
                }
            }
            for (int i = 0; i < nflows && i < 20; i++) {
                int row = 2 + i;
                if (row >= body_h) break;
                char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
                struct in_addr sa, da;
                sa.s_addr = htonl(sorted[i].key.sip);
                da.s_addr = htonl(sorted[i].key.dip);
                inet_ntop(AF_INET, &sa, sip, sizeof(sip));
                inet_ntop(AF_INET, &da, dip, sizeof(dip));
                const char *proto_str = "???";
                switch (sorted[i].key.proto) {
                    case PROTO_TCP: proto_str = "TCP"; break;
                    case PROTO_UDP: proto_str = "UDP"; break;
                    case PROTO_ICMP: proto_str = "ICMP"; break;
                }
                mvwprintw(detail_win, row, 1,
                          "%2d. %s:%u -> %s:%u  [%s]  pkts=%u bytes=%lu",
                          i + 1, sip, sorted[i].key.sp, dip, sorted[i].key.dp,
                          proto_str, sorted[i].pkt_cnt, sorted[i].byte_cnt);
            }
            pthread_mutex_unlock(&flow_hash_mutex);
            break;

        case VIEW_APPINFO:
            /* DNS domains + TLS SNI + HTTP methods */
            /* NOTE: ui_mutex already held by ui_refresh(), so access packets[] directly */
            {
                int row = 1;
                char domains[50][256];
                int nd = 0;
                char snis[50][256];
                int ns = 0;
                char methods[20][16];
                int nm = 0;

                for (int i = 0; i < pkt_count; i++) {
                    /* Collect DNS domains (dedup) */
                    if (packets[i].dns_domain[0] != '\0' && nd < 50) {
                        int dup = 0;
                        for (int j = 0; j < nd; j++) {
                            if (strcmp(domains[j], packets[i].dns_domain) == 0)
                                { dup = 1; break; }
                        }
                        if (!dup) {
                            strncpy(domains[nd], packets[i].dns_domain, 255);
                            domains[nd][255] = '\0';
                            nd++;
                        }
                    }
                    /* Collect TLS SNIs (dedup) */
                    if (packets[i].tls_sni[0] != '\0' && ns < 50) {
                        int dup = 0;
                        for (int j = 0; j < ns; j++) {
                            if (strcmp(snis[j], packets[i].tls_sni) == 0)
                                { dup = 1; break; }
                        }
                        if (!dup) {
                            strncpy(snis[ns], packets[i].tls_sni, 255);
                            snis[ns][255] = '\0';
                            ns++;
                        }
                    }
                    /* Collect HTTP methods (dedup) */
                    if (packets[i].http_method[0] != '\0' && nm < 20) {
                        int dup = 0;
                        for (int j = 0; j < nm; j++) {
                            if (strcmp(methods[j], packets[i].http_method) == 0)
                                { dup = 1; break; }
                        }
                        if (!dup) {
                            strncpy(methods[nm], packets[i].http_method, 15);
                            methods[nm][15] = '\0';
                            nm++;
                        }
                    }
                }

                if (nd > 0) {
                    mvwprintw(detail_win, row++, 1, "=== DNS Queries (%d) ===", nd);
                    for (int i = 0; i < nd && row < body_h; i++) {
                        mvwprintw(detail_win, row++, 3, "[%d] %s", i + 1, domains[i]);
                    }
                }

                if (ns > 0) {
                    if (row < body_h - 2) mvwprintw(detail_win, row++, 1, " ");
                    mvwprintw(detail_win, row++, 1, "=== TLS SNI (%d) ===", ns);
                    for (int i = 0; i < ns && row < body_h; i++) {
                        mvwprintw(detail_win, row++, 3, "[%d] %s", i + 1, snis[i]);
                    }
                }

                if (nm > 0) {
                    if (row < body_h - 2) mvwprintw(detail_win, row++, 1, " ");
                    mvwprintw(detail_win, row++, 1, "=== HTTP Methods ===");
                    for (int i = 0; i < nm && row < body_h; i++) {
                        mvwprintw(detail_win, row++, 3, "- %s", methods[i]);
                    }
                }

                if (nd == 0 && ns == 0 && nm == 0) {
                    mvwprintw(detail_win, 2, 1, "(No application-layer data yet)");
                }
            }
            break;
        default:
            break;
        }
    } else if (detail_win) {
        /* No packet selected — show hint */
        if (pkt_count == 0)
            mvwprintw(detail_win, 1, 1, "( No packets captured yet )");
        else
            mvwprintw(detail_win, 1, 1, "( No packets match current filter )");
    }

    pthread_mutex_unlock(&ui_mutex);

    /* ── Bottom status bar ── */
    char dur[32];
    human_duration(dur, sizeof(dur), ui_start_time);
    char pause_text[32] = "";
    if (capture_pause) strcpy(pause_text, "[PAUSED]");

    /* Capture loss-rate snapshot */
    u_long recv  = __atomic_load_n(&g_pcap_recv, __ATOMIC_RELAXED);
    u_long drop  = __atomic_load_n(&g_pcap_drop, __ATOMIC_RELAXED);
    u_long ifdrop = __atomic_load_n(&g_pcap_ifdrop, __ATOMIC_RELAXED);
    char loss_str[32] = "";
    if (recv + drop + ifdrop > 0) {
        double lr = (double)(drop + ifdrop) / (double)(recv + drop + ifdrop) * 100.0;
        snprintf(loss_str, sizeof(loss_str), "Loss:%.2f%%", lr);
    } else {
        snprintf(loss_str, sizeof(loss_str), "Loss:--");
    }

    /* Snapshot traffic stats for display */
    traffic_stat snap;
    stat_snapshot(&snap);

    const char *view_names[] = {"Packets", "Traffic", "AppInfo"};
    mvwprintw(stats_win, 0, 1,
              "Sniffer | iface:%s filter:%s uptime:%s total:%lu %s",
              g_capture_dev, g_capture_filter, dur, total_packets, loss_str);
    mvwprintw(stats_win, 1, 1,
              "View: %s | TCP:%d UDP:%d ICMP:%d DNS:%d HTTP:%d(Req:%d Resp:%d) Flows:%d | %s%s",
              view_names[g_current_view],
              snap.pkt_tcp, snap.pkt_udp, snap.pkt_icmp,
              snap.pkt_dns, snap.pkt_http,
              snap.pkt_http_req, snap.pkt_http_resp,
              tcp_flow_active_count(),
              pause_text, g_filter_hint);
    mvwprintw(stats_win, 2, 1,
              "Hotkeys: <-/->=View  Up/Dn=Select  PgUp/PgDn=Page  Space=Pause  C=Clear  Q=Quit");

    if (list_win)   wrefresh(list_win);
    if (detail_win) wrefresh(detail_win);
    if (stats_win)  wrefresh(stats_win);
    if (title_win)  wrefresh(title_win);
    doupdate();
}

void ui_set_status(const char *status)
{
    pthread_mutex_lock(&ui_mutex);
    strncpy(ui_status, status, sizeof(ui_status) - 1);
    ui_status[sizeof(ui_status) - 1] = '\0';
    pthread_mutex_unlock(&ui_mutex);
}

/* ── Input handler: drain ALL pending keystrokes, not just one ── */
/* Returns 1 if a display-changing key was pressed (view/filter/clear/quit) */
int ui_handle_input(void)
{
    int ch;
    int handled = 0;
    int need_refresh = 0;
    const int MAX_KEYS_PER_CALL = 20;  /* safety limit */

    while ((ch = getch()) != ERR && handled < MAX_KEYS_PER_CALL) {
        handled++;

        /* Left/Right arrows: switch views (Tab removed — caused freeze on repeat) */
        if (ch == KEY_LEFT) {
            g_current_view = (g_current_view == 0) ? VIEW_COUNT - 1 : g_current_view - 1;
            detail_scroll = 0;
            need_refresh = 1;
            continue;
        }
        if (ch == KEY_RIGHT) {
            g_current_view = (g_current_view + 1) % VIEW_COUNT;
            detail_scroll = 0;
            need_refresh = 1;
            continue;
        }
    /* Quick-view keys: 7=Packets, 8=Traffic, 9=AppInfo */
    if (ch == '7') { g_current_view = VIEW_PACKETS; detail_scroll = 0; need_refresh = 1; continue; }
    if (ch == '8') { g_current_view = VIEW_TRAFFIC; detail_scroll = 0; need_refresh = 1; continue; }
    if (ch == '9') { g_current_view = VIEW_APPINFO; detail_scroll = 0; need_refresh = 1; continue; }

    /* Filter hotkeys 1~6 */
    if (ch == '1') {
        g_ui_filter = UI_FILTER_ALL;
        strcpy(g_filter_hint, "Filter: All");
        need_refresh = 1;
        continue;
    }
    if (ch == '2') {
        g_ui_filter = UI_FILTER_TCP;
        strcpy(g_filter_hint, "Filter: TCP");
        need_refresh = 1;
        continue;
    }
    if (ch == '3') {
        g_ui_filter = UI_FILTER_UDP;
        strcpy(g_filter_hint, "Filter: UDP");
        need_refresh = 1;
        continue;
    }
    if (ch == '4') {
        g_ui_filter = UI_FILTER_ICMP;
        strcpy(g_filter_hint, "Filter: ICMP");
        need_refresh = 1;
        continue;
    }
    if (ch == '5') {
        g_ui_filter = UI_FILTER_IPV4;
        strcpy(g_filter_hint, "Filter: IPv4");
        need_refresh = 1;
        continue;
    }
    if (ch == '6') {
        g_ui_filter = UI_FILTER_IPV6;
        strcpy(g_filter_hint, "Filter: IPv6");
        need_refresh = 1;
        continue;
    }

    if (ch == ' ') {
        capture_pause = !capture_pause;
        ui_set_status(capture_pause ? "PAUSED" : "Capturing");
        need_refresh = 1;
        continue;
    }
    if (ch == 'q' || ch == 'Q') {
        exit_flag = 1;
        need_refresh = 1;
        continue;
    }
    if (ch == 'c' || ch == 'C') {
        pthread_mutex_lock(&ui_mutex);
        pkt_count = 0;
        pkt_selected = 0;
        list_scroll = 0;
        detail_scroll = 0;
        total_packets = 0;
        memset(packets, 0, sizeof(packets));
        pthread_mutex_unlock(&ui_mutex);
        need_refresh = 1;
        continue;
    }

    if (pkt_count == 0) continue;

    pthread_mutex_lock(&ui_mutex);
    if (ch == KEY_UP) {
        /* Walk backwards through filtered packets */
        int cur = pkt_selected;
        while (cur > 0) {
            cur--;
            if (match_filter(packets[cur].proto_tag)) {
                pkt_selected = cur;
                break;
            }
        }
    } else if (ch == KEY_DOWN) {
        int cur = pkt_selected;
        while (cur < pkt_count - 1) {
            cur++;
            if (match_filter(packets[cur].proto_tag)) {
                pkt_selected = cur;
                break;
            }
        }
	    } else if (ch == KEY_NPAGE) {
	        /* Page down: move selection down by one screenful in filtered list */
	        int h, w, body_h, list_w, detail_w;
	        calc_layout(&h, &w, &body_h, &list_w, &detail_w);
	        int page = body_h - 2;
	        if (page < 1) page = 1;
	        int skipped = 0;
	        int cur = pkt_selected;
	        while (cur < pkt_count - 1 && skipped < page) {
	            cur++;
	            if (match_filter(packets[cur].proto_tag)) skipped++;
	        }
	        if (skipped > 0) pkt_selected = cur;
	    } else if (ch == KEY_PPAGE) {
	        /* Page up: move selection up by one screenful in filtered list */
	        int h, w, body_h, list_w, detail_w;
	        calc_layout(&h, &w, &body_h, &list_w, &detail_w);
	        int page = body_h - 2;
	        if (page < 1) page = 1;
	        int skipped = 0;
	        int cur = pkt_selected;
	        while (cur > 0 && skipped < page) {
	            cur--;
	            if (match_filter(packets[cur].proto_tag)) skipped++;
	        }
	        if (skipped > 0) pkt_selected = cur;
	    }
	    pthread_mutex_unlock(&ui_mutex);
    }
    return need_refresh;
}
