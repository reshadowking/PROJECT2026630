#ifndef SRC_UI_H
#define SRC_UI_H

#include <pcap.h>



void ui_init(void);
void ui_shutdown(void);
void ui_refresh(void);
void ui_handle_input(void);
void ui_add_packet(const struct pcap_pkthdr *hdr, const u_char *data);
void ui_set_status(const char *status);
void draw_layout(void);



#endif
