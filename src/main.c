#include "common.h"
#include "capture.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
int g_use_ncurses = 0;
volatile int exit_flag = 0;

// 纯标记，无任何打印IO
void sig_exit(int sig) {
    (void)sig;
    exit_flag = 1;
}

void usage() {
    printf("Usage: sudo ./sniffer [-i dev] [-f filter] [-w save.pcap] [-r read.pcap]\n");
    printf("Example: sudo ./sniffer -i ens33 -f \"tcp port 80\"\n");
}

int main(int argc, char** argv) {
    signal(SIGINT, sig_exit);
    char dev[32] = "";
    char filter[256] = "";
    char wfile[128] = "";
    char rfile[128] = "";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i")) {
            if (i + 1 >= argc) {
                usage();
                fprintf(stderr, "Error: -i requires an interface name\n");
                return -1;
            }
            strncpy(dev, argv[++i], sizeof(dev) - 1);
            dev[sizeof(dev) - 1] = '\0';
        } else if (!strcmp(argv[i], "-f")) {
            if (i + 1 >= argc) {
                usage();
                fprintf(stderr, "Error: -f requires a filter string\n");
                return -1;
            }
            strncpy(filter, argv[++i], sizeof(filter) - 1);
            filter[sizeof(filter) - 1] = '\0';
        } else if (!strcmp(argv[i], "-w")) {
            if (i + 1 >= argc) {
                usage();
                fprintf(stderr, "Error: -w requires a save file path\n");
                return -1;
            }
            strncpy(wfile, argv[++i], sizeof(wfile) - 1);
            wfile[sizeof(wfile) - 1] = '\0';
        } else if (!strcmp(argv[i], "-r")) {
            if (i + 1 >= argc) {
                usage();
                fprintf(stderr, "Error: -r requires a pcap file path\n");
                return -1;
            }
            strncpy(rfile, argv[++i], sizeof(rfile) - 1);
            rfile[sizeof(rfile) - 1] = '\0';
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
        save_pcap(wfile);
    if (strlen(rfile) == 0)
        stat_thread_start();
    printf("Capture running... Ctrl+C exit\n");
    fflush(stdout);
    start_loop(&exit_flag);

    // 主线程跳出循环后，清空输出缓冲区再清理
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