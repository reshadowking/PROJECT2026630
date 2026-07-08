#include "common.h"
#include "capture.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
#include "ui.h"

int g_use_ncurses = 0;
int use_ui = 0;
UiFilterType g_ui_filter = UI_FILTER_ALL;
char g_filter_hint[64] = "Filter: All";
volatile int exit_flag = 0;
volatile int capture_pause = 0;
char g_capture_dev[32] = {0};
char g_capture_filter[256] = {0};

void packet_callback(u_char *u, const struct pcap_pkthdr *hdr, const u_char *data);

void sig_exit(int sig)
{
    (void)sig;
    exit_flag = 1;
}

void usage(void)
{
    printf("Usage: sudo ./sniffer [-u] [-i dev] [-f filter] [-w save.pcap] [-r read.pcap]\n");
    printf("  -u      Enable ncurses GUI\n");
    printf("  -i dev  Network interface for live capture\n");
    printf("  -f expr BPF filter expression\n");
    printf("  -w file Save capture to pcap file\n");
    printf("  -r file Parse offline pcap file\n");
    printf("Example: sudo ./sniffer -u -i ens33 -f \"tcp port 80\"\n");
}

int main(int argc, char** argv)
{
    signal(SIGINT, sig_exit);

    char dev[32] = "";
    char filter[256] = "";
    char wfile[128] = "";
    char rfile[128] = "";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-u")) {
            use_ui = 1;
        } else if (!strcmp(argv[i], "-i")) {
            i++;
            strncpy(dev, argv[i], sizeof(dev) - 1);
            dev[sizeof(dev) - 1] = '\0';
            strncpy(g_capture_dev, dev, sizeof(g_capture_dev) - 1);
        } else if (!strcmp(argv[i], "-f")) {
            i++;
            strncpy(filter, argv[i], sizeof(filter) - 1);
            filter[sizeof(filter) - 1] = '\0';
            strncpy(g_capture_filter, filter, sizeof(g_capture_filter) - 1);
        } else if (!strcmp(argv[i], "-w")) {
            i++;
            strncpy(wfile, argv[i], sizeof(wfile) - 1);
            wfile[sizeof(wfile) - 1] = '\0';
        } else if (!strcmp(argv[i], "-r")) {
            i++;
            strncpy(rfile, argv[i], sizeof(rfile) - 1);
            rfile[sizeof(rfile) - 1] = '\0';
        } else {
            usage();
            return -1;
        }
    }

    if (strlen(rfile) == 0 && strlen(dev) == 0) {
        usage();
        fprintf(stderr, "Error: Must specify -i dev for live capture or -r file for offline parsing\n");
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

    if (strlen(wfile)) {
        int ret_dump = save_pcap(wfile);
        if (ret_dump != 0) {
            fprintf(stderr, "Failed to open dump file\n");
        }
    }

    if (strlen(rfile) == 0 && use_ui) {
        stat_thread_start();
        ui_init();

        struct pcap_pkthdr *hdr;
        const u_char *pkt_data;
        int has_new_pkt = 0;
        time_t last_refresh_tm = time(NULL);

        while (!exit_flag) {
            has_new_pkt = 0;
            while ((ret = pcap_next_ex(g_handle, &hdr, &pkt_data)) == 1) {
                packet_callback(NULL, hdr, pkt_data);
                has_new_pkt = 1;
            }
            if (ret == -1) {
                /* Error — continue to allow UI to show state */
                usleep(10000);
                continue;
            }

            time_t now_tm = time(NULL);
            if (has_new_pkt && (now_tm - last_refresh_tm >= 0)) {
                ui_refresh();
                last_refresh_tm = now_tm;
            }
            ui_handle_input();
            usleep(10000);
        }

        ui_shutdown();
    } else {
        if (strlen(rfile) == 0)
            stat_thread_start();
        printf("Capture running... Ctrl+C to exit\n");
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
