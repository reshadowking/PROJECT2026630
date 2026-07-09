#include "common.h"
#include "capture.h"
#include "parser.h"
#include "ui.h"
#include "traffic_stat.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <string.h>
#include <stdio.h>

pcap_t *g_handle = NULL;
pcap_dumper_t *g_dumper = NULL;
extern volatile int capture_pause;

/* ── Periodic loss-rate sampling ── */
static time_t g_last_stat_ts = 0;

void capture_update_loss_stats(void)
{
    if (!g_handle) return;
    /* Only sample every 2 seconds to reduce syscall overhead */
    time_t now = time(NULL);
    if (now - g_last_stat_ts < 2) return;
    g_last_stat_ts = now;

    struct pcap_stat ps;
    if (pcap_stats(g_handle, &ps) == 0) {
        __atomic_store_n(&g_pcap_recv,   ps.ps_recv,   __ATOMIC_RELAXED);
        __atomic_store_n(&g_pcap_drop,   ps.ps_drop,   __ATOMIC_RELAXED);
        __atomic_store_n(&g_pcap_ifdrop, ps.ps_ifdrop, __ATOMIC_RELAXED);
    }
}

void packet_callback(u_char *u, const struct pcap_pkthdr *hdr, const u_char *data)
{
    (void)u;
    if (g_dumper) {
        pcap_dump((u_char *)g_dumper, hdr, data);
    }
    parse_packet(hdr, data);

    /* Skip UI buffer if paused */
    if (use_ui && !capture_pause) {
        ui_add_packet(hdr, data);
    }
}

int open_capture(const char *dev, const char *filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Use immediate mode + larger buffer for high-speed capture */
    g_handle = pcap_create(dev, errbuf);
    if (!g_handle) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return -1;
    }

    /* 32 MB kernel buffer for 1 Gbps traffic */
    pcap_set_buffer_size(g_handle, 32 * 1024 * 1024);
    pcap_set_snaplen(g_handle, 65535);
    pcap_set_promisc(g_handle, 1);
    pcap_set_timeout(g_handle, 1);  /* 1ms timeout for low latency */
    pcap_set_immediate_mode(g_handle, 1);

    int status = pcap_activate(g_handle);
    if (status < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(g_handle));
        pcap_close(g_handle);
        g_handle = NULL;
        return -1;
    }

    if (filter && strlen(filter) > 0) {
        struct bpf_program fp;
        bpf_u_int32 netmask, ip;
        if (pcap_lookupnet(dev, &ip, &netmask, errbuf) != 0) {
            netmask = 0xffffff00; /* fallback */
        }
        if (pcap_compile(g_handle, &fp, filter, 0, netmask) < 0 ||
            pcap_setfilter(g_handle, &fp) < 0) {
            fprintf(stderr, "Failed to compile/set BPF filter: %s\n", pcap_geterr(g_handle));
            return -1;
        }
    }

    /* Non-blocking for UI integration */
    pcap_setnonblock(g_handle, 1, errbuf);
    return 0;
}

int open_pcap_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_offline(path, errbuf);
    if (!g_handle) {
        fprintf(stderr, "open pcap file failed: %s\n", errbuf);
        return -1;
    }
    return 0;
}

int save_pcap(const char *path)
{
    if (!g_handle) return -1;
    g_dumper = pcap_dump_open(g_handle, path);
    if (g_dumper) {
        return 0;
    }
    return -1;
}

void start_loop(volatile int *flag)
{
    struct pcap_pkthdr *hdr;
    const u_char *data;
    while (!*flag) {
        int ret = pcap_next_ex(g_handle, &hdr, &data);
        if (ret == 1) {
            packet_callback(NULL, hdr, data);
            /* Periodically update loss stats from pcap */
            capture_update_loss_stats();
        } else if (ret == -1 || ret == -2) {
            /* Error (-1) or EOF (-2) — stop loop */
            break;
        }
        /* ret == 0: timeout, continue */
    }
}

void close_capture(void)
{
    if (g_dumper) { pcap_dump_close(g_dumper); g_dumper = NULL; }
    if (g_handle) { pcap_close(g_handle); g_handle = NULL; }
}
