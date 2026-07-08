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
    g_handle = pcap_open_live(dev, 65535, 1, 100, errbuf);
    if (!g_handle) {
        fprintf(stderr, "pcap open live failed: %s\n", errbuf);
        return -1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int fd = pcap_fileno(g_handle);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(fd, SIOCSIFFLAGS, &ifr);

    if (filter && strlen(filter) > 0) {
        struct bpf_program fp;
        bpf_u_int32 netmask, ip;
        pcap_lookupnet(dev, &ip, &netmask, errbuf);
        if (pcap_compile(g_handle, &fp, filter, 0, netmask) < 0 ||
            pcap_setfilter(g_handle, &fp) < 0) {
            fprintf(stderr, "Failed to compile/set BPF filter\n");
            return -1;
        }
    }

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
        } else if (ret == -1) {
            /* Error during capture — stop loop */
            break;
        }
    }
}

void close_capture(void)
{
    if (g_dumper) { pcap_dump_close(g_dumper); g_dumper = NULL; }
    if (g_handle) { pcap_close(g_handle); g_handle = NULL; }
}
