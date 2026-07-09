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

		    if (use_ui) {
		        stat_thread_start();
		        ui_init();
		
		        struct pcap_pkthdr *hdr;
		        const u_char *pkt_data;
		        struct timespec last_refresh_ts, now_ts;
		        clock_gettime(CLOCK_MONOTONIC, &last_refresh_ts);
		        const long REFRESH_NS = 100000000L;  /* regular refresh every 100ms */
		        const long COOLDOWN_NS = 50000000L;  /* force-refresh cooldown 50ms */
		        struct timespec last_force_ts = last_refresh_ts;
		        /* When reading from pcap file, keep UI alive after EOF */
		        int pcap_eof = (strlen(rfile) > 0) ? 0 : 0;
	
	        while (!exit_flag) {
	            /* ── Drain pending keyboard input first (always responsive) ── */
	            int need_refresh = ui_handle_input();
	
	            /* ── Grab one packet (non-blocking, ~1ms timeout) ── */
	            int ret = 0;
	            if (!pcap_eof) {
	                ret = pcap_next_ex(g_handle, &hdr, &pkt_data);
	                if (ret == 1) {
	                    packet_callback(NULL, hdr, pkt_data);
	                } else if (ret == -1) {
	                    usleep(5000);
	                } else if (ret == -2) {
	                    pcap_eof = 1;  /* file exhausted, keep UI alive for browsing */
	                }
	            }

            /* ── Refresh UI at fixed interval, or once per cooldown on keypress ── */
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            long elapsed_ns = (now_ts.tv_sec - last_refresh_ts.tv_sec) * 1000000000L
                            + (now_ts.tv_nsec - last_refresh_ts.tv_nsec);
            long force_elapsed = (now_ts.tv_sec - last_force_ts.tv_sec) * 1000000000L
                               + (now_ts.tv_nsec - last_force_ts.tv_nsec);

            /* Force refresh on keypress, but only once per cooldown window */
            int do_refresh = 0;
            if (need_refresh && force_elapsed >= COOLDOWN_NS) {
                do_refresh = 1;
                last_force_ts = now_ts;
            } else if (elapsed_ns >= REFRESH_NS) {
                do_refresh = 1;
            }

            if (do_refresh) {
                extern void capture_update_loss_stats(void);
                capture_update_loss_stats();
                ui_refresh();
                clock_gettime(CLOCK_MONOTONIC, &last_refresh_ts);
            }

            /* Yield CPU when idle */
            if (ret == 0 && !do_refresh) usleep(500);
        }

        ui_shutdown();
    } else {
        stat_thread_start();
        printf("Capture running... Ctrl+C to exit\n");
        fflush(stdout);
        start_loop(&exit_flag);
    }

    fflush(stdout);
    printf("\n==== Cleanup start ====\n");
    fflush(stdout);

    /* Print final statistics before stopping thread */
    if (!use_ui) {
        print_stat();
    }

    stat_thread_stop();
    tcp_flow_clear_all();
    close_capture();
    printf("Exit success\n");
    fflush(stdout);
    return 0;
}
