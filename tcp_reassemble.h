#ifndef TCP_REASSEMBLE_H
#define TCP_REASSEMBLE_H
#include "common.h"
void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp, u_uint seq, u_char *pay, int len);
#endif