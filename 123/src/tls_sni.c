#include "tls_sni.h"
#include <stdint.h>
typedef unsigned char  uint8;
typedef unsigned short uint16;
typedef unsigned int   uint32;

void tls_extract_sni(const u_char *data, int len, char *sni_out) {
    memset(sni_out, 0, 256);
    if (len < 9) return;
    if (data[0] != 0x16) return;
    uint16 rec_len = (data[1] << 8) | data[2];
    int rec_end = 5 + rec_len;
    if (rec_end > len) return;
    int ptr = 5;
    uint8 hs_type = data[ptr];
    if (hs_type != 0x01) return;
    ptr += 4; // 删除未使用hs_len变量，消除警告
    ptr += 2 + 32;
    uint8 sid_len = data[ptr++];
    ptr += sid_len;
    uint16 cipher_len = (data[ptr] << 8) | data[ptr+1];
    ptr += 2 + cipher_len;
    uint8 comp_len = data[ptr++];
    ptr += comp_len;
    if (ptr + 2 > rec_end) return;
    uint16 ext_total = (data[ptr] << 8) | data[ptr+1];
    ptr += 2;
    while (ptr + 4 <= rec_end && ext_total > 0) {
        uint16 ext_type = (data[ptr] << 8) | data[ptr+1];
        uint16 ext_len = (data[ptr+2] << 8) | data[ptr+3];
        ptr += 4;
        if (ext_type == 0) {
            if (ptr + 2 > rec_end) break;
            uint16 name_len = (data[ptr] << 8) | data[ptr+1];
            ptr += 2;
            if (ptr + name_len <= rec_len && name_len < 255) {
                strncpy(sni_out, (const char*)(data+ptr), name_len);
            }
            break;
        }
        ptr += ext_len;
        ext_total -= (4 + ext_len);
    }
}