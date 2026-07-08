#include "dns.h"

/* Recursively decode a DNS name at *p, stopping at null terminator.
 * Writes the dotted hostname into 'out' (up to 'out_sz' bytes).
 * Returns the number of bytes consumed from 'p' (including trailing null). */
static int decode_dns_name(const u_char *p, int plen, char *out, int out_sz)
{
    int offset = 0;       /* bytes consumed from p            */
    int wrote  = 0;       /* bytes written to out             */
    int dot    = 0;       /* whether we need to prepend '.'   */

    while (plen > 0) {
        u_char label_len = p[0];

        /* End of name */
        if (label_len == 0) {
            if (wrote > 0 && out[wrote - 1] != '.')
                out[wrote++] = '\0';
            return offset + 1;
        }

        /* Compression pointer (0xC0xx) — not expected in query section,
         * but handle gracefully by stopping */
        if ((label_len & 0xC0) == 0xC0) {
            break;
        }

        /* Sanity: label length must be <= 63 */
        if (label_len > 63 || offset + 1 + label_len > plen) {
            break;
        }

        if (dot && wrote < out_sz - 1)
            out[wrote++] = '.';
        dot = 1;

        int remain = out_sz - wrote - 1;
        if (remain <= 0) break;
        if (label_len > (unsigned int)remain)
            label_len = (unsigned int)remain;

        memcpy(out + wrote, p + 1, label_len);
        wrote += label_len;

        offset += 1 + label_len;
        p += 1 + label_len;
        plen -= 1 + label_len;
    }

    out[wrote] = '\0';
    return offset;
}

void parse_dns(const u_char *payload, int len, char *out_domain, int domain_sz)
{
    if (len < (int)sizeof(struct dns_hdr)) return;

    struct dns_hdr *dns = (struct dns_hdr *)payload;
    uint16_t qdcount = ntohs(dns->qdcount);

    if (qdcount == 0) {
        if (out_domain && domain_sz > 0) out_domain[0] = '\0';
        return;
    }

    const u_char *name_ptr = payload + sizeof(struct dns_hdr);
    int remaining = len - (int)sizeof(struct dns_hdr);

    /* Decode the first QD name */
    if (out_domain && domain_sz > 0) {
        decode_dns_name(name_ptr, remaining, out_domain, domain_sz);
    }
}
