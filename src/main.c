#include "common.h"
#include "capture.h"
#include "traffic_stat.h"

int g_use_ncurses = 0;

void sig_exit(int sig) {
    (void)sig;
    stat_thread_stop();
    close_capture();
    printf("\nExit success\n");
    exit(0);
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
        if (!strcmp(argv[i], "-i"))
            strcpy(dev, argv[++i]);
        else if (!strcmp(argv[i], "-f"))
            strcpy(filter, argv[++i]);
        else if (!strcmp(argv[i], "-w"))
            strcpy(wfile, argv[++i]);
        else if (!strcmp(argv[i], "-r"))
            strcpy(rfile, argv[++i]);
        else {
            usage();
            return -1;
        }
    }

    // 实时抓包必须指定网卡
    if (strlen(rfile) == 0 && strlen(dev) == 0) {
        usage();
        fprintf(stderr, "Error: Must specify -i dev for live capture\n");
        return -1;
    }

    if (strlen(rfile)) {
        if (open_pcap_file(rfile) != 0)
            return -1;
    } else {
        // 空过滤传NULL，修复BPF编译错误
        int ret;
        if (strlen(filter) > 0)
            ret = open_capture(dev, filter);
        else
            ret = open_capture(dev, NULL);
        if (ret != 0)
            return -1;
    }

    if (strlen(wfile))
        save_pcap(wfile);

    // 离线回放不启动统计线程
    if (strlen(rfile) == 0)
        stat_thread_start();

    printf("Capture running... Ctrl+C exit\n");
    start_loop();
    close_capture();
    return 0;
}