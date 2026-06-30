#ifndef TRAFFIC_STAT_H
#define TRAFFIC_STAT_H
#include "common.h"
extern traffic_stat g_stat;
void stat_thread_start();
void stat_thread_stop();
void print_stat();
#endif