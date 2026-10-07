#include "ip_header.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Identificador incremental simple para el campo "id" del header IP. */
static uint16_t ip_id_counter = 54321;

void build_ip_header(ip_header_t *iph, const char *src_ip, const char *dst_ip,
                     uint16_t payload_len, uint8_t ttl, uint8_t protocol) {
    memset(iph, 0, sizeof(ip_header_t));

    iph->ihl_version  = (4 << 4) | 5;   /* Version 4, IHL 5 -> 5*4 = 20 bytes */
    iph->tos          = 0;
    iph->total_length = htons((uint16_t)(sizeof(ip_header_t) + payload_len));
    iph->id           = htons(ip_id_counter++);
    iph->flags_fo     = htons(0x4000);  /* Flag "Don't Fragment" activado */
    iph->ttl          = ttl;            /* <-- TTL variable por salto */
    iph->protocol     = protocol;       /* IPPROTO_ICMP = 1 */
    iph->checksum     = 0;              /* Se calcula despues, con checksum.c */
    iph->src_addr     = inet_addr(src_ip);
    iph->dst_addr     = inet_addr(dst_ip);
}
