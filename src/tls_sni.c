/*
 * tls_sni.c — TLS 握手解析模块
 *
 * 功能:
 *   1. 从 ClientHello 中提取 SNI (Server Name Indication) 域名
 *   2. 解析 ServerHello 中的密码套件和压缩方法
 *
 * 限制: 仅处理单条 TLS 记录中包含完整握手消息的场景,
 *       不支持跨记录的碎片化握手。
 */

#include "tls_sni.h"
#include <stdint.h>

/*
 * tls_extract_sni — 从 TLS ClientHello 中提取 SNI 域名
 *
 * 解析 TLS record → Handshake → ClientHello → Extensions → SNI
 *
 *   data:    TLS 记录起始地址 (包含 record header)
 *   len:     数据长度
 *   sni_out: 输出 SNI 域名 (最多 255 字节, 以 '\0' 结尾)
 */
void tls_extract_sni(const u_char *data, int len, char *sni_out)
{
    memset(sni_out, 0, 256);
    if (len < 9) return;
    if (data[0] != 0x16) return;

    uint16_t rec_len = ((uint16_t)data[3] << 8) | data[4];
    int rec_end = 5 + (int)rec_len;
    if (rec_end > len) rec_end = len;

    int ptr = 5;
    uint8_t hs_type = data[ptr];
    if (hs_type != 0x01) return;  /* not ClientHello */

    ptr += 4;                      /* skip handshake header */
    ptr += 2 + 32;                 /* skip client version + random */
    uint8_t sid_len = data[ptr++]; /* session id length */
    ptr += sid_len;
    uint16_t cipher_len = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
    ptr += 2 + (int)cipher_len;
    uint8_t comp_len = data[ptr++];
    ptr += comp_len;

    if (ptr + 2 > rec_end) return;
    uint16_t ext_total = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
    ptr += 2;

    while (ptr + 4 <= rec_end && ext_total > 0) {
        uint16_t ext_type = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
        uint16_t ext_len  = ((uint16_t)data[ptr + 2] << 8) | data[ptr + 3];
        ptr += 4;

        if (ext_type == 0x0000) {
            /* SNI extension (type=0) */
            if (ptr + 2 > rec_end) break;
            uint16_t server_name_list_len = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
            (void)server_name_list_len;
            ptr += 2;
            if (ptr + 3 > rec_end) break;
            /* ServerName type (should be 0 = host_name) */
            uint8_t name_type = data[ptr];
            ptr++;
            uint16_t name_len = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
            ptr += 2;
            if (name_type == 0 && ptr + (int)name_len <= rec_end && name_len < 255) {
                memcpy(sni_out, data + ptr, name_len);
                sni_out[name_len] = '\0';
                LOG_DEBUG("TLS SNI extracted: %s", sni_out);
            } else {
                LOG_WARN("TLS SNI extraction failed: name_len=%d invalid", name_len);
            }
            break;
        }
        ptr += ext_len;
        ext_total -= (4 + (uint16_t)ext_len);
    }
}

/*
 * tls_cipher_name — 将 TLS 密码套件 ID 转为可读名称
 */
static const char *tls_cipher_name(uint16_t id)
{
    switch (id) {
        case 0x0005: return "RSA_WITH_RC4_128_SHA";
        case 0x000A: return "RSA_WITH_3DES_EDE_CBC_SHA";
        case 0x002F: return "RSA_WITH_AES_128_CBC_SHA";
        case 0x0033: return "DHE_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "RSA_WITH_AES_256_CBC_SHA";
        case 0x003C: return "RSA_WITH_AES_128_CBC_SHA256";
        case 0x003D: return "RSA_WITH_AES_256_CBC_SHA256";
        case 0x009C: return "RSA_WITH_AES_128_GCM_SHA256";
        case 0x009D: return "RSA_WITH_AES_256_GCM_SHA384";
        case 0x009E: return "DHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009F: return "DHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC013: return "ECDHE_RSA_WITH_AES_128_CBC_SHA";
        case 0xC014: return "ECDHE_RSA_WITH_AES_256_CBC_SHA";
        case 0xC027: return "ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        case 0xC028: return "ECDHE_RSA_WITH_AES_256_CBC_SHA384";
        case 0xC02B: return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC02C: return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC02F: return "ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xCCA8: return "ECDHE_RSA_WITH_CHACHA20_POLY1305";
        case 0xCCA9: return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305";
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        default:     return "UNKNOWN";
    }
}

/*
 * tls_compression_method — 压缩方法 ID → 名称
 */
static const char *tls_compression_method(uint8_t id)
{
    switch (id) {
        case 0: return "null";
        case 1: return "DEFLATE";
        default: return "?";
    }
}

/*
 * tls_parse_serverhello — 解析 TLS ServerHello 消息
 *
 * 提取 TLS 版本、密码套件、压缩方法、会话 ID
 *
 *   data:     TLS 记录起始地址
 *   len:      数据长度
 *   info_out: 输出信息字符串 (最多 512 字节)
 */
void tls_parse_serverhello(const u_char *data, int len, char *info_out)
{
    memset(info_out, 0, 512);
    if (len < 9) return;
    if (data[0] != 0x16) return;

    uint16_t rec_len = ((uint16_t)data[3] << 8) | data[4];
    int rec_end = 5 + (int)rec_len;
    if (rec_end > len) rec_end = len;

    int ptr = 5;
    uint8_t hs_type = data[ptr];
    if (hs_type != 0x02) return;  /* not ServerHello */
    ptr++;  /* skip handshake type */

    /* handshake length (3 bytes) */
    uint32_t hs_len = ((uint32_t)data[ptr] << 16) | ((uint32_t)data[ptr + 1] << 8) | data[ptr + 2];
    (void)hs_len;
    ptr += 3;

    uint16_t tls_ver = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
    ptr += 2;

    /* random (32 bytes): skip gmt_unix_time(4) + random_bytes(28) */
    uint32_t gmt_time = ((uint32_t)data[ptr] << 24) | ((uint32_t)data[ptr + 1] << 16) |
                        ((uint32_t)data[ptr + 2] << 8) | data[ptr + 3];
    (void)gmt_time;
    ptr += 28;

    /* session id */
    uint8_t sid_len = data[ptr++];
    if (ptr + sid_len > rec_end) return;
    char sid_hex[65] = {0};
    for (int i = 0; i < sid_len && i < 32; i++) {
        snprintf(sid_hex + i * 2, 3, "%02x", data[ptr + i]);
    }
    ptr += sid_len;

    /* cipher suite */
    if (ptr + 2 > rec_end) return;
    uint16_t cipher_id = ((uint16_t)data[ptr] << 8) | data[ptr + 1];
    ptr += 2;

    /* compression method */
    if (ptr >= rec_end) return;
    uint8_t comp_id = data[ptr++];

    snprintf(info_out, 512,
             "ver=0x%04X cipher=%s(0x%04X) comp=%s sid_len=%d sid=%s",
             tls_ver,
             tls_cipher_name(cipher_id), cipher_id,
             tls_compression_method(comp_id),
             sid_len, sid_hex);
}
