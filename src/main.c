#include "common.h"
#include "capture.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "ui.h"
int g_use_ncurses = 0;
int use_ui = 0;
volatile int exit_flag = 0;
volatile int capture_pause = 0;
char g_capture_dev[32] = {0};
char g_capture_filter[256] = {0};
void packet_callback(u_char *u, const struct pcap_pkthdr *hdr, const u_char *data);
void sig_exit(int sig) {
    (void)sig;
    exit_flag = 1;
    fprintf(stderr, "[DEBUG main.c] SIGINT received, exit_flag=1\n");
}
void usage() {
    printf("Usage: sudo ./sniffer [-u] [-i dev] [-f filter] [-w save.pcap] [-r read.pcap]\n");
    printf("  -u      启用ncurses图形UI界面\n");
    printf("  -i dev  指定网卡实时抓包\n");
    printf("  -f expr BPF过滤表达式\n");
    printf("  -w file 保存抓包到pcap\n");
    printf("  -r file 读取pcap离线解析\n");
    printf("Example: sudo ./sniffer -u -i ens33 -f \"tcp port 80\"\n");
}
int main(int argc, char** argv) {
    signal(SIGINT, sig_exit);
    char dev[32] = "";
    char filter[256] = "";
    char wfile[128] = "";
    char rfile[128] = "";
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-u")) {
            use_ui = 1;
            fprintf(stderr, "[DEBUG main.c] arg -u parsed, use_ui=1\n");
        } else if (!strcmp(argv[i], "-i")) {
            i++;
            strncpy(dev, argv[i], sizeof(dev) - 1);
            dev[sizeof(dev) - 1] = '\0';
            strncpy(g_capture_dev, dev, sizeof(g_capture_dev)-1);
            fprintf(stderr, "[DEBUG main.c] arg -i dev=%s\n", dev);
        } else if (!strcmp(argv[i], "-f")) {
            i++;
            strncpy(filter, argv[i], sizeof(filter) - 1);
            filter[sizeof(filter) - 1] = '\0';
            strncpy(g_capture_filter, filter, sizeof(g_capture_filter)-1);
            fprintf(stderr, "[DEBUG main.c] arg -f filter=%s\n", filter);
        } else if (!strcmp(argv[i], "-w")) {
            i++;
            strncpy(wfile, argv[i], sizeof(wfile) - 1);
            wfile[sizeof(wfile) - 1] = '\0';
            fprintf(stderr, "[DEBUG main.c] arg -w file=%s\n", wfile);
        } else if (!strcmp(argv[i], "-r")) {
            i++;
            strncpy(rfile, argv[i], sizeof(rfile) - 1);
            rfile[sizeof(rfile) - 1] = '\0';
            fprintf(stderr, "[DEBUG main.c] arg -r file=%s\n", rfile);
        } else {
            usage();
            return -1;
        }
    }
    if (strlen(rfile) == 0 && strlen(dev) == 0) {
        usage();
        fprintf(stderr, "Error: Must specify -i dev for live capture\n");
        return -1;
    }
    int ret;
    if (strlen(rfile)) {
        if (open_pcap_file(rfile) != 0)
            return -1;
    } else {
        if (strlen(filter) > 0)
            ret = open_capture(dev, filter);
        else
            ret = open_capture(dev, NULL);
        if (ret != 0)
            return -1;
    }
    if (strlen(wfile))
    {
        int ret_dump = save_pcap(wfile);
        if (ret_dump != 0)
        {
            fprintf(stderr, "Failed to open dump file\n");
        }
    }
    if (strlen(rfile) == 0 && use_ui)
    {
        fprintf(stderr, "[DEBUG main.c] Enter UI branch\n");
        stat_thread_start();
        fprintf(stderr, "[DEBUG main.c] stat_thread_start done, run ui_init\n");
        ui_init();
        fprintf(stderr, "[DEBUG main.c] ui_init finished, start capture loop\n");
        struct pcap_pkthdr *hdr;
        const u_char *pkt_data;
        int ret;
        int has_new_pkt = 0;
        time_t last_refresh_tm = time(NULL);
        while (!exit_flag)
        {
            has_new_pkt = 0;
            while ((ret = pcap_next_ex(g_handle, &hdr, &pkt_data)) == 1)
            {
                fprintf(stderr, "[DEBUG main.c] pcap_next_ex get packet, call packet_callback\n");
                packet_callback(NULL, hdr, pkt_data);
                has_new_pkt = 1;
            }
            if (ret == -1)
            {
                fprintf(stderr, "[DEBUG main.c] pcap_next_ex error ret=-1\n");
            }
            time_t now_tm = time(NULL);
            if (has_new_pkt && (now_tm - last_refresh_tm >= 0))
            {
                fprintf(stderr, "[DEBUG main.c] new packet arrive, run ui_refresh\n");
                ui_refresh();
                last_refresh_tm = now_tm;
            }
            ui_handle_input();
            usleep(1000);
        }
        ui_shutdown();
        fprintf(stderr, "[DEBUG main.c] ui_shutdown done\n");
    }
    else
    {
        fprintf(stderr, "[DEBUG main.c] Enter text mode branch\n");
        if (strlen(rfile) == 0)
            stat_thread_start();
        printf("Capture running... Ctrl+C exit\n");
        fflush(stdout);
        start_loop(&exit_flag);
    }
    fflush(stdout);
    printf("\n==== Cleanup start ====\n");
    fflush(stdout);
    stat_thread_stop();
    tcp_flow_clear_all();
    close_capture();
    printf("Exit success\n");
    fflush(stdout);
    return 0;
}