#ifndef UI_H
#define UI_H

#include <pcap.h>

void ui_init(void);
void ui_shutdown(void);
void ui_refresh(void);
void ui_handle_input(void);
void ui_add_packet(const struct pcap_pkthdr *hdr, const u_char *data);
void ui_set_status(const char *status);
void draw_layout(void);

/* Generate human-readable protocol layer text */
void gen_proto_info(char *out, size_t buf_len, const u_char *pkt, uint32_t pkt_len);

/* Application-layer query APIs (for the AppInfo tab) */
int  ui_get_dns_domains(char domains[][256], int max_n);
int  ui_get_tls_snis(char snis[][256], int max_n);

#endif
