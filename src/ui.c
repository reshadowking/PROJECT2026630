#include "ui.h"
#include <string.h>
#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include <ncurses.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#define MAX_UI_PACKETS 100
#define MAX_UI_DETAIL 4096
#define MAX_SUMMARY 128
typedef struct {
    char summary[MAX_SUMMARY];
    char detail[MAX_UI_DETAIL];
    unsigned int len;
    struct timeval ts;
} ui_packet;
extern volatile int exit_flag;
static WINDOW *title_win = NULL;
static WINDOW *list_win = NULL;
static WINDOW *detail_win = NULL;
static WINDOW *stats_win = NULL;
static ui_packet packets[MAX_UI_PACKETS];
static int pkt_count = 0;
static int pkt_selected = 0;
static unsigned long total_packets = 0;
static int detail_scroll = 0;
static pthread_mutex_t ui_mutex = PTHREAD_MUTEX_INITIALIZER;
static int saved_stdout = -1;
static time_t ui_start_time = 0;
static char ui_status[128] = "Waiting for packets...";
static int debug_fd = -1;
static void ui_debug_log(const char *fmt, ...) {
    if (debug_fd < 0) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n > sizeof(buf)) n = sizeof(buf);
        write(debug_fd, buf, n);
        write(debug_fd, "\n", 1);
    }
}
static void redirect_output_to_null(void) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0) return;
    saved_stdout = dup(STDOUT_FILENO);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
}
static void restore_output(void) {
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
        saved_stdout = -1;
    }
}
static void human_duration(char *buf, size_t cap, time_t start) {
    time_t now = time(NULL);
    int s = (int)(now - start);
    int h = s / 3600; s %= 3600;
    int m = s / 60; s %= 60;
    snprintf(buf, cap, "%02dh%02dm", h, m);
}
static void extract_summary(const struct pcap_pkthdr *hdr, const u_char *data, char *out, size_t oc) {
    out[0] = '\0';
    if (hdr->len <= 14) {
        snprintf(out, oc, "len=%u ETH", hdr->len);
        return;
    }
    const unsigned char *eth = data;
    uint16_t eth_type = (eth[12] << 8) | eth[13];
    if (eth_type == 0x0800 && hdr->len > 34) {
        const unsigned char *ip = data + 14;
        uint8_t ip_ver = (ip[0] >> 4) & 0x0F;
        if (ip_ver == 4) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ip + 12, src, sizeof(src));
            inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));
            uint8_t proto = ip[9];
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            if (proto == 6 && hdr->len > 14 + ihl + 20) {
                uint16_t sport = (ip[ihl + 14] << 8) | ip[ihl + 15];
                uint16_t dport = (ip[ihl + 16] << 8) | ip[ihl + 17];
                snprintf(out, oc, "%u %s:%u->%s:%u TCP", hdr->len, src, sport, dst, dport);
            } else if (proto == 17 && hdr->len > 14 + ihl + 8) {
                uint16_t sport = (ip[ihl + 14] << 8) | ip[ihl + 15];
                uint16_t dport = (ip[ihl + 16] << 8) | ip[ihl + 17];
                snprintf(out, oc, "%u %s:%u->%s:%u UDP", hdr->len, src, sport, dst, dport);
            } else {
                snprintf(out, oc, "%u %s->%s IP%u", hdr->len, src, dst, proto);
            }
        }
    } else {
        snprintf(out, oc, "%u ETH 0x%04x", hdr->len, eth_type);
    }
}
void draw_layout() {
    int h, w;
    getmaxyx(stdscr, h, w);
    int title_h = 3;
    int stats_h = 3;
    int body_h = h - title_h - stats_h;
    int list_w = w * 60 / 100;
    int detail_w = w - list_w - 1;
    if (!title_win) title_win = newwin(title_h, w, 0, 0);
    if (!list_win) list_win = newwin(body_h, list_w, title_h, 0);
    if (!detail_win) detail_win = newwin(body_h, detail_w, title_h, list_w+1);
    if (!stats_win) stats_win = newwin(stats_h, w, title_h + body_h, 0);
    wbkgd(title_win, COLOR_PAIR(1));
    wbkgd(list_win, COLOR_PAIR(2));
    wbkgd(detail_win, COLOR_PAIR(2));
    wbkgd(stats_win, COLOR_PAIR(3));
    werase(title_win); box(title_win, 0, 0);
    werase(list_win); box(list_win, 0, 0);
    werase(detail_win); box(detail_win, 0, 0);
    werase(stats_win); box(stats_win, 0, 0);
    char dur[32];
    human_duration(dur, sizeof(dur), ui_start_time);
    mvwprintw(title_win, 1, 2, "Sniffer UI | uptime: %s | iface: %s | filter: %s | pkts: %lu | %s",
            dur, strlen(g_capture_dev) ? g_capture_dev : "-",
            strlen(g_capture_filter) ? g_capture_filter : "-", total_packets, ui_status);
    mvwprintw(list_win, 1, 2, "#  Len  Summary");
    wrefresh(title_win);
    wrefresh(list_win);
    wrefresh(detail_win);
    wrefresh(stats_win);
}
void ui_init(void) {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    clear();
    timeout(0);
    keypad(stdscr, TRUE);
    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLUE);
        init_pair(2, COLOR_WHITE, COLOR_BLACK);
        init_pair(3, COLOR_YELLOW, COLOR_BLACK);
        init_pair(4, COLOR_CYAN, COLOR_BLACK);
        init_pair(5, COLOR_GREEN, COLOR_BLACK);
    }
    ui_start_time = time(NULL);
    // ONLY create windows ONCE during initialization, NOT every refresh
    draw_layout();
    doupdate();

    // Keep stdout redirect disabled for debug
    // redirect_output_to_null();

    debug_fd = open("/tmp/sniffer_ui.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    ui_debug_log("ui_init: started");

    // Static test packet to verify drawing
    pthread_mutex_lock(&ui_mutex);
    ui_packet test_pkt = {0};
    test_pkt.len = 999;
    strcpy(test_pkt.summary, "TEST STATIC PACKET — IF THIS SHOWS, DRAWING WORKS");
    packets[0] = test_pkt;
    pkt_count = 1;
    total_packets = 1;
    pkt_selected = 0;
    pthread_mutex_unlock(&ui_mutex);
}
void ui_shutdown(void) {
    restore_output();
    if (title_win) { delwin(title_win); title_win = NULL; }
    if (list_win)  { delwin(list_win); list_win = NULL; }
    if (detail_win){ delwin(detail_win); detail_win = NULL; }
    if (stats_win) { delwin(stats_win); stats_win = NULL; }
    endwin();
    if (debug_fd >= 0) { ui_debug_log("ui_shutdown"); close(debug_fd); debug_fd = -1; }
}
void ui_add_packet(const struct pcap_pkthdr *hdr, const u_char *data) {
    ui_packet p = {0};
    p.len = hdr->len;
    p.ts = hdr->ts;
    extract_summary(hdr, data, p.summary, sizeof(p.summary));
    size_t n = hdr->len > 128 ? 128 : hdr->len;
    char *d = p.detail;
    snprintf(d, MAX_UI_DETAIL, "len=%u\n", hdr->len);
    for (size_t i = 0; i < n; i++) {
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "%02x ", data[i]);
        strncat(d, tmp, MAX_UI_DETAIL - strlen(d) - 1);
        if ((i+1)%16==0) strncat(d, "\n", MAX_UI_DETAIL - strlen(d) - 1);
    }
    pthread_mutex_lock(&ui_mutex);
    fprintf(stderr, "[DEBUG ui.c] ui_add_packet lock acquired, pkt_count=%d\n", pkt_count);

    if (pkt_count < MAX_UI_PACKETS) {
        packets[pkt_count] = p;
        pkt_count++;
        pkt_selected = pkt_count - 1;
    } else {
        // Slide buffer, pkt_count remains MAX_UI_PACKETS permanently
        memmove(packets, packets + 1, (MAX_UI_PACKETS - 1) * sizeof(ui_packet));
        packets[MAX_UI_PACKETS - 1] = p;
        pkt_selected = MAX_UI_PACKETS - 1;
    }
    total_packets++;
    pthread_mutex_unlock(&ui_mutex);
    fprintf(stderr, "[DEBUG ui.c] packet saved to UI buffer, total_packets=%lu summary=%s\n", total_packets, p.summary);
    ui_debug_log("ui_add_packet: len=%u total=%lu summary=%.40s", p.len, total_packets, p.summary);
}
void ui_refresh(void) {
    int h, w;
    getmaxyx(stdscr, h, w);
    int title_h = 3;
    int stats_h = 3;
    int body_h = h - title_h - stats_h;
    int list_w = w * 6 / 10;
    int detail_w = w - list_w - 1;

    // Only erase content, DO NOT recreate windows
    werase(list_win);
    box(list_win, 0, 0);
    mvwprintw(list_win, 1, 2, "#  Len  Summary");

    werase(detail_win);
    box(detail_win, 0, 0);

    werase(stats_win);
    box(stats_win, 0, 0);

    int visible = body_h - 3;
    pthread_mutex_lock(&ui_mutex);

    // Add double boundary protection to avoid out-of-bounds
    for (int i = 0; i < visible && i < pkt_count; i++) {
        int row = 2 + i;
        if (i == pkt_selected) wattron(list_win, A_REVERSE);
        mvwprintw(list_win, row, 2, "%3d %4u  %.40s",
            i+1, packets[i].len, packets[i].summary);
        if (i == pkt_selected) wattroff(list_win, A_REVERSE);
    }

    // Draw detail panel
    if (pkt_count > 0) {
        if (pkt_selected >= pkt_count)
            pkt_selected = pkt_count - 1;
        char *d = packets[pkt_selected].detail;
        int max_lines = body_h - 2;
        int row = 1;
        char linebuf[detail_w + 1];
        const char *p = d;
        int line_no = 0;
        while (*p && row <= max_lines) {
            int c = 0;
            while (*p && *p != '\n' && c < detail_w) linebuf[c++] = *p++;
            linebuf[c] = '\0';
            if (*p) p++;
            if (line_no >= detail_scroll) {
                mvwprintw(detail_win, row, 2, "%s", linebuf);
                row++;
            }
            line_no++;
        }
    } else {
        mvwprintw(list_win, 2, 2, "Waiting for packets...");
    }

    pthread_mutex_unlock(&ui_mutex);

    // Stats bar
    mvwprintw(stats_win, 1, 2,
        "TCP:%u UDP:%u ICMP:%u HTTP:%u TotalPkt:%u TotalByte:%lu ActiveFlows:%d",
        g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp, g_stat.pkt_http,
        g_stat.pkt_total, g_stat.byte_total, tcp_flow_active_count());

    // Critical sync to physical terminal screen
    wrefresh(title_win);
    wrefresh(list_win);
    wrefresh(detail_win);
    wrefresh(stats_win);
    doupdate();
}
void ui_set_status(const char *status) {
    pthread_mutex_lock(&ui_mutex);
    strncpy(ui_status, status, sizeof(ui_status) - 1);
    ui_status[sizeof(ui_status) - 1] = '\0';
    pthread_mutex_unlock(&ui_mutex);
    ui_debug_log("ui_set_status: %s", ui_status);
}
void ui_handle_input(void) {
    int ch = getch();
    if (ch == ERR) return;
    // SPACE key: pause / resume capture core logic
    if (ch == ' ') {
        capture_pause = !capture_pause;
        if (capture_pause) {
            ui_set_status("PAUSED - Press SPACE to resume");
        } else {
            ui_set_status("Capturing traffic");
        }
        return;
    }
    if (ch == 'q' || ch == 'Q') {
        exit_flag = 1;
        return;
    }
    if (ch == 'c' || ch == 'C') {
        pthread_mutex_lock(&ui_mutex);
        pkt_count = 0;
        pkt_selected = 0;
        total_packets = 0;
        detail_scroll = 0;
        memset(packets, 0, sizeof(packets));
        pthread_mutex_unlock(&ui_mutex);
        return;
    }
    if (pkt_count == 0) return;
    pthread_mutex_lock(&ui_mutex);
    if (ch == KEY_UP) {
        if (pkt_selected > 0) pkt_selected--;
    } else if (ch == KEY_DOWN) {
        if (pkt_selected < pkt_count - 1) pkt_selected++;
    } else if (ch == KEY_NPAGE) {
        detail_scroll += 10;
    } else if (ch == KEY_PPAGE) {
        if (detail_scroll > 0) detail_scroll -= 10;
    }
    pthread_mutex_unlock(&ui_mutex);
}