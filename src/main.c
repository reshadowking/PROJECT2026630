/*
 * main.c — 程序入口
 *
 * 命令行参数:
 *   -u          启用 ncurses 图形 UI
 *   -i dev      指定网卡实时抓包
 *   -f expr     BPF 过滤表达式
 *   -w file     保存抓包到 pcap 文件
 *   -r file     读取 pcap 文件离线回放
 *
 * 示例:
 *   sudo ./sniffer -u -i ens33 -f "tcp port 80"
 *   ./sniffer -r capture.pcap
 */

#include "common.h"
#include "capture.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "ui.h"

int g_use_ncurses = 0;
int use_ui = 0;
UiFilterType g_ui_filter = UI_FILTER_ALL;
UiTab g_ui_tab = UI_TAB_PACKET_LIST;
char g_filter_hint[64] = "过滤: 全部";
volatile int exit_flag = 0;
volatile int capture_pause = 0;
char g_capture_dev[32] = {0};
char g_capture_filter[256] = {0};

/*
 * sig_exit — 信号处理函数
 *   sig: 信号编号 (SIGINT / SIGTERM)
 */
void sig_exit(int sig)
{
    (void)sig;
    exit_flag = 1;
    LOG_INFO("%s received, exit_flag set to 1", sig == SIGINT ? "SIGINT" : "SIGTERM");
}

/*
 * usage — 打印使用说明
 */
static void usage(void)
{
    printf("Usage: sudo ./sniffer [-u] [-i dev] [-f filter] [-w save.pcap] [-r read.pcap]\n");
    printf("  -u      启用 ncurses 图形 UI 界面\n");
    printf("  -i dev  指定网卡实时抓包\n");
    printf("  -f expr BPF 过滤表达式\n");
    printf("  -w file 保存抓包到 pcap\n");
    printf("  -r file 读取 pcap 离线解析\n");
    printf("Example: sudo ./sniffer -u -i ens33 -f \"tcp port 80\"\n");
    printf("\nUI 操作按键说明:\n");
    printf("  TAB    切换标签页 (报文列表 / 流量统计 / 应用层信息)\n");
    printf("  1-6    协议过滤 (ALL/TCP/UDP/ICMP/IPv4/IPv6)\n");
    printf("  ↑↓     选择报文\n");
    printf("  PgUp/PgDn/Home/End  滚动报文列表\n");
    printf("  Space  暂停/恢复抓包\n");
    printf("  C      清除报文列表\n");
    printf("  Q      退出程序\n");
}

/*
 * main — 主函数
 */
int main(int argc, char **argv)
{
    signal(SIGINT, sig_exit);
    signal(SIGTERM, sig_exit);

    char dev[32] = "";
    char filter[256] = "";
    char wfile[128] = "";
    char rfile[128] = "";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-u")) {
            use_ui = 1;
            LOG_INFO("arg -u: ncurses UI enabled");
        } else if (!strcmp(argv[i], "-i")) {
            i++;
            strncpy(dev, argv[i], sizeof(dev) - 1);
            dev[sizeof(dev) - 1] = '\0';
            strncpy(g_capture_dev, argv[i], sizeof(g_capture_dev) - 1);
            LOG_INFO("arg -i: dev=%s", dev);
        } else if (!strcmp(argv[i], "-f")) {
            i++;
            strncpy(filter, argv[i], sizeof(filter) - 1);
            filter[sizeof(filter) - 1] = '\0';
            strncpy(g_capture_filter, argv[i], sizeof(g_capture_filter) - 1);
            LOG_INFO("arg -f: filter=%s", filter);
        } else if (!strcmp(argv[i], "-w")) {
            i++;
            strncpy(wfile, argv[i], sizeof(wfile) - 1);
            wfile[sizeof(wfile) - 1] = '\0';
            LOG_INFO("arg -w: save to %s", wfile);
        } else if (!strcmp(argv[i], "-r")) {
            i++;
            strncpy(rfile, argv[i], sizeof(rfile) - 1);
            rfile[sizeof(rfile) - 1] = '\0';
            LOG_INFO("arg -r: read from %s", rfile);
        } else {
            usage();
            return -1;
        }
    }

    if (strlen(rfile) == 0 && strlen(dev) == 0) {
        usage();
        fprintf(stderr, "Error: Must specify -i dev for live capture\n");
        log_flush();
        return -1;
    }

    int ret;
    if (strlen(rfile)) {
        if (open_pcap_file(rfile) != 0) {
            log_flush();
            return -1;
        }
    } else {
        if (strlen(filter) > 0)
            ret = open_capture(dev, filter);
        else
            ret = open_capture(dev, NULL);
        if (ret != 0) {
            log_flush();
            return -1;
        }
    }

    if (strlen(wfile)) {
        int ret_dump = save_pcap(wfile);
        if (ret_dump != 0) {
            LOG_ERROR("save_pcap failed, path=%s", wfile);
        }
    }

    /* 初始化 HTTP 配对日志 */
    http_pair_log_init();

    pkt_queue_init(&g_pkt_queue, PKT_QUEUE_SIZE);

    stat_thread_start();
    LOG_INFO("stat_thread started");

    parser_workers_start(PARSER_WORKERS, &g_pkt_queue);
    LOG_INFO("parser_workers started, count=%d", PARSER_WORKERS);

    if (use_ui) {
        LOG_INFO("entering UI mode");
        ui_init();

        /* UI 初始化可能因 initscr 失败而 fallback */
        if (use_ui) {
            capture_thread_start();
            LOG_INFO("capture_thread started");

            unsigned long last_total = ui_get_total_packets();
            time_t last_force_refresh = time(NULL);

            while (!exit_flag) {
                ui_drain_ring();
                unsigned long cur_total = ui_get_total_packets();
                time_t now = time(NULL);
                int need_refresh = (cur_total != last_total) || (now - last_force_refresh >= 1);

                int input_changed = ui_handle_input();
                if (input_changed) need_refresh = 1;

                if (need_refresh) {
                    ui_refresh();
                    last_total = cur_total;
                    last_force_refresh = now;
                }
                usleep(50000);
            }

            ui_shutdown();
            LOG_INFO("ui_shutdown done");
        } else {
            /* fallback: UI 初始化失败, 退回到文本模式 */
            capture_thread_start();
            LOG_INFO("capture_thread started (text fallback)");

            printf("Capture running... Ctrl+C to exit\n");
            fflush(stdout);

            while (!exit_flag) {
                usleep(100000);
            }

            /* print final statistics in text-fallback mode */
            printf("\n");
            print_stat();
            fflush(stdout);
        }
    } else {
        capture_thread_start();
        LOG_INFO("capture_thread started");

        LOG_INFO("entering text mode, running...");
        printf("Capture running... Ctrl+C to exit\n");
        fflush(stdout);

        while (!exit_flag) {
            usleep(100000);
        }

        /* print final statistics in text mode */
        printf("\n");
        print_stat();
        fflush(stdout);
    }

    fflush(stdout);
    printf("\n==== Cleanup start ====\n");
    fflush(stdout);

    LOG_INFO("cleanup: stopping capture thread");
    capture_thread_stop();

    LOG_INFO("cleanup: stopping parser workers");
    parser_workers_stop();

    LOG_INFO("cleanup: stopping stat thread");
    stat_thread_stop();

    LOG_INFO("cleanup: clearing tcp flows");
    tcp_flow_clear_all();

    LOG_INFO("cleanup: closing HTTP pair log");
    http_pair_log_close();

    log_flush();

    LOG_INFO("cleanup: closing capture");
    close_capture();

    LOG_INFO("cleanup: destroying pkt_queue");
    pkt_queue_destroy(&g_pkt_queue);

    printf("Exit success\n");
    fflush(stdout);
    return 0;
}
