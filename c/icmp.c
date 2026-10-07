#include "icmp.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>

int build_icmp_echo(uint8_t *buf, uint16_t id, uint16_t seq, int payload_len) {
    icmp_echo_t *icmp = (icmp_echo_t *)buf;
    icmp->type     = ICMP_ECHO_REQUEST;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = htons(id);
    icmp->seq      = htons(seq);

    /* Relleno con un patron reconocible, al estilo de ping. */
    for (int i = 0; i < payload_len; i++) {
        buf[ICMP_HEADER_LEN + i] = (uint8_t)(0x40 + (i & 0x3F));
    }

    int total = (int)ICMP_HEADER_LEN + payload_len;
    icmp->checksum = calculate_checksum((uint16_t *)buf, total);
    return total;
}

int parse_icmp_reply(const uint8_t *pkt, int len,
                     uint16_t *out_id, uint16_t *out_seq) {
    if (len < 20) return -1;                       /* ni siquiera un header IP */

    int ip_ihl = (pkt[0] & 0x0F) * 4;              /* longitud del header IP   */
    if (len < ip_ihl + (int)ICMP_HEADER_LEN) return -1;

    const icmp_echo_t *icmp = (const icmp_echo_t *)(pkt + ip_ihl);
    uint8_t type = icmp->type;

    if (type == ICMP_ECHO_REPLY) {
        /* El destino nos respondio: id/seq vienen directos. */
        *out_id  = ntohs(icmp->id);
        *out_seq = ntohs(icmp->seq);
        return ICMP_ECHO_REPLY;
    }

    if (type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACH) {
        /* Tras los 8 bytes del header de error ICMP viene el datagrama
         * original: header IP interno + primeros 8 bytes (nuestro Echo). */
        const uint8_t *inner = pkt + ip_ihl + 8;
        int inner_avail = len - ip_ihl - 8;
        if (inner_avail < 20) return -1;

        int inner_ihl = (inner[0] & 0x0F) * 4;
        if (inner_avail < inner_ihl + (int)ICMP_HEADER_LEN) return -1;

        const icmp_echo_t *orig = (const icmp_echo_t *)(inner + inner_ihl);
        *out_id  = ntohs(orig->id);
        *out_seq = ntohs(orig->seq);
        return type;
    }

    return -1; /* otro tipo de ICMP que no nos interesa */
}
