#ifndef TCP_REASSEMBLE_H
#define TCP_REASSEMBLE_H
#include "common.h"

/* Add a TCP segment to the reassembly engine.
 * sip, dip, sp, dp: IPs and ports (network byte order converted to host)
 * seq: TCP sequence number (host byte order)
 * flags: TCP flags byte (for SYN/FIN/RST detection)
 * pay, len: TCP payload */
void tcp_flow_add(u_int sip, u_int dip, u_short sp, u_short dp,
                  u_uint seq, u_char flags, const u_char *pay, int len);

/* Get the number of active flows */
int tcp_flow_active_count(void);

/* Get the number of extracted HTTP request/response pairs */
int tcp_flow_http_pairs(void);

/* Get the log file path */
const char *tcp_flow_log_path(void);

/* Clear all flows */
void tcp_flow_clear_all(void);

#endif
