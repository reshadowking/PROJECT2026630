#include "tls_sni.h"

void tls_extract_sni(const u_char *data, int len, char *sni_out) {
    memset(sni_out, 0, 256);
    if (len < 5)
        return;
    // 仅处理TLS握手报文
    if (data[0] != 0x16)
        return;

    int offset = 5;
    if (offset + 1 > len)
        return;
    uint16_t handshake_len = (data[offset] << 8) | data[offset + 1];
    offset += 3;

    if (offset >= len)
        return;
    // 只解析ClientHello
    if (data[offset] != 0x01)
        return;

    offset += 46;
    if (offset + 2 > len)
        return;
    uint16_t ext_total_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // 遍历所有扩展，寻找SNI(类型0)
    while (offset + 4 <= len && ext_total_len > 0) {
        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (ext_type == 0) {
            if (offset + 2 > len)
                break;
            uint16_t sni_name_len = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            if (offset + sni_name_len <= len && sni_name_len < 255) {
                strncpy(sni_out, (const char *)(data + offset), sni_name_len);
            }
            break;
        }
        offset += ext_len;
        ext_total_len -= (4 + ext_len);
    }
}