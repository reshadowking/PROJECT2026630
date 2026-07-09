#ifndef TLS_SNI_H
#define TLS_SNI_H
#include "common.h"
void tls_extract_sni(const u_char *data, int len, char *sni_out);
void tls_parse_serverhello(const u_char *data, int len, char *info_out);
#endif