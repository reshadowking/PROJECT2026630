#include "common.h"
#include "capture.h"
#include "parser.h"
#include "ui.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <string.h>
#include <stdio.h>
pcap_t *g_handle = NULL;
pcap_dumper_t *g_dumper = NULL;
extern volatile int capture_pause;
void packet_callback(u_char *u, const struct pcap_pkthdr *hdr, const u_char *data)
{
    (void)u;
    fprintf(stderr, "[DEBUG capture.c] packet_callback triggered, len=%d\n", hdr->len);
    if (g_dumper)
    {
        pcap_dump((u_char *)g_dumper, hdr, data);
        fprintf(stderr, "[DEBUG capture.c] write pcap dump success\n");
    }
    parse_packet(hdr, data);
    fprintf(stderr, "[DEBUG capture.c] parse_packet finished\n");
    // Skip UI buffer if paused
    if (use_ui && !capture_pause)
    {
        fprintf(stderr, "[DEBUG capture.c] use_ui=1, call ui_add_packet\n");
        ui_add_packet(hdr, data);
        ui_set_status("packet received");
        fprintf(stderr, "[DEBUG capture.c] ui_add_packet done\n");
    } else if (capture_pause) {
        fprintf(stderr, "[DEBUG capture.c] capture paused, skip ui add\n");
    } else {
        fprintf(stderr, "[DEBUG capture.c] use_ui=0 skip ui\n");
    }
}
int open_capture(const char *dev, const char *filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(dev, 65535, 1, 100, errbuf);
    if (!g_handle)
    {
        fprintf(stderr, "pcap open live failed: %s\n", errbuf);
        return -1;
    }
    fprintf(stderr, "[DEBUG capture.c] open_capture success dev=%s\n", dev);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int fd = pcap_fileno(g_handle);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (filter && strlen(filter) > 0)
    {
        struct bpf_program fp;
        bpf_u_int32 netmask, ip;
        pcap_lookupnet(dev, &ip, &netmask, errbuf);
        if (pcap_compile(g_handle, &fp, filter, 0, netmask) <0 || pcap_setfilter(g_handle, &fp)<0) return -1;
        fprintf(stderr, "[DEBUG capture.c] BPF filter loaded: %s\n", filter);
    }
    pcap_setnonblock(g_handle, 1, errbuf);
    return 0;
}
int open_pcap_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_offline(path, errbuf);
    if (!g_handle)
    {
        fprintf(stderr, "open pcap file failed: %s\n", errbuf);
        return -1;
    }
    fprintf(stderr, "[DEBUG capture.c] open offline pcap %s success\n", path);
    return 0;
}
int save_pcap(const char *path)
{
    if (!g_handle) return -1;
    g_dumper = pcap_dump_open(g_handle, path);
    if (g_dumper) {
        fprintf(stderr, "[DEBUG capture.c] dump file open %s success\n", path);
        return 0;
    }
    return -1;
}
void start_loop(volatile int *flag)
{
    struct pcap_pkthdr *hdr;
    const u_char *data;
    fprintf(stderr, "[DEBUG capture.c] start_loop enter\n");
    while (!*flag) {
        int ret = pcap_next_ex(g_handle, &hdr, &data);
        if (ret == 1)
        {
            packet_callback(NULL, hdr, data); // Fix: replace wrong packet() -> packet_callback
        } else if (ret == -1) {
            fprintf(stderr, "[DEBUG capture.c] pcap_next_ex error\n");
        }
    }
}
void close_capture()
{
    if (g_dumper) { pcap_dump_close(g_dumper); g_dumper = NULL; }
    if (g_handle) { pcap_close(g_handle); g_handle = NULL; }
    fprintf(stderr, "[DEBUG capture.c] capture closed\n");
}