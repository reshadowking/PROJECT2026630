#include "common.h"
#include "parser.h"
pcap_t *g_handle = NULL;
pcap_dumper_t *g_dumper = NULL;
int open_capture(const char *dev, const char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(dev, BUF_MAX, 1, 100, errbuf);
    if (!g_handle) {
        fprintf(stderr, "open dev fail: %s\n", errbuf);
        return -1;
    }
    if (filter != NULL && strlen(filter) > 0) {
        struct bpf_program fp;
        bpf_u_int32 mask, net;
        pcap_lookupnet(dev, &net, &mask, errbuf);
        if (pcap_compile(g_handle, &fp, filter, 0, mask) == -1) {
            fprintf(stderr, "compile filter fail: %s\n", pcap_geterr(g_handle));
            return -1;
        }
        if (pcap_setfilter(g_handle, &fp) == -1) {
            fprintf(stderr, "set filter fail: %s\n", pcap_geterr(g_handle));
            return -1;
        }
    }
    pcap_setnonblock(g_handle, 1, errbuf);
    return 0;
}
int open_pcap_file(const char *file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_offline(file, errbuf);
    if (!g_handle) {
        fprintf(stderr, "open pcap fail: %s\n", errbuf);
        return -1;
    }
    return 0;
}
int save_pcap(const char *path) {
    g_dumper = pcap_dump_open(g_handle, path);
    if (!g_dumper) {
        fprintf(stderr, "dump open fail\n");
        return -1;
    }
    return 0;
}
void close_capture() {
    if (g_dumper) {
        pcap_dump_flush(g_dumper);
        pcap_dump_close(g_dumper);
    }
    if (g_handle)
        pcap_close(g_handle);
}
void packet_callback(u_char *u, const struct pcap_pkthdr *hdr, const u_char *data) {
    if (g_dumper)
        pcap_dump((u_char *)g_dumper, hdr, data);
    parse_packet(hdr, data);
}
void start_loop(volatile int *exit_flag) {
    struct pcap_pkthdr *hdr;
    const u_char *pkt_data;
    int ret;
    while (!*exit_flag) {
        ret = pcap_next_ex(g_handle, &hdr, &pkt_data);
        if (ret == 1) {
            packet_callback(NULL, hdr, pkt_data);
        } else if (ret == -1) {
            fprintf(stderr, "pcap read error: %s\n", pcap_geterr(g_handle));
            break;
        }
        usleep(10000); // 缩短休眠，快速检测Ctrl+C
    }
}