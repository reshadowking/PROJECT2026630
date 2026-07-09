#ifndef CAPTURE_H
#define CAPTURE_H
#include <pcap.h>
int open_capture(const char *dev, const char *filter);
int open_pcap_file(const char *file);
int save_pcap(const char *path);
void close_capture();
void start_loop(volatile int *exit_flag);
void capture_update_loss_stats(void);
#endif