#ifndef TCP_REASSEMBLE_H
#define TCP_REASSEMBLE_H
#include "common.h"
// 正确顺序：sip,dip,sp,dp,seq,pay,len
void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp, u_uint seq, const u_char *pay, int len);
void tcp_flow_clear_all();
int tcp_flow_active_count();
#endif