#ifndef TLS_SNI_H
#define TLS_SNI_H
#include "common.h"
// 形参添加 const，匹配传入的 const u_char*
void tls_extract_sni(const u_char *data, int len, char *sni_out);
#endif