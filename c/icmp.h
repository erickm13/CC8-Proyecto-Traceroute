#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

/* Tipos ICMP relevantes para Traceroute (RFC 792). */
#define ICMP_ECHO_REPLY     0   /* respuesta del DESTINO a nuestro Echo       */
#define ICMP_DEST_UNREACH   3   /* destino inalcanzable (puerto/host/red)     */
#define ICMP_ECHO_REQUEST   8   /* nuestro probe                              */
#define ICMP_TIME_EXCEEDED 11   /* un router descarto el paquete (TTL=0)      */

/*
 * Header ICMP de Echo (8 bytes): tipo, codigo, checksum, identificador y
 * numero de secuencia. Para Echo Request/Reply los ultimos 4 bytes son
 * id + seq, que usamos para emparejar cada probe con su respuesta.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_echo_t;
#pragma pack(pop)

#define ICMP_HEADER_LEN sizeof(icmp_echo_t)

/*
 * Arma un ICMP Echo Request en 'buf' (header + 'payload_len' bytes de datos),
 * con el id y seq dados, y calcula su checksum.
 * Devuelve la longitud total del mensaje ICMP (header + datos).
 */
int build_icmp_echo(uint8_t *buf, uint16_t id, uint16_t seq, int payload_len);

/*
 * Analiza un paquete IP recibido (empieza en el header IP) y determina si es
 * una respuesta relevante a alguno de nuestros probes.
 *
 * Devuelve el TIPO ICMP reconocido (0, 3 u 11), o -1 si no es relevante.
 * En out_id/out_seq coloca el id y seq del Echo original:
 *   - Echo Reply (0): vienen directo en el header ICMP de la respuesta.
 *   - Time Exceeded (11) / Dest Unreachable (3): el cuerpo del error ICMP
 *     incluye el header IP original + los primeros 8 bytes del datagrama
 *     original (que son justamente nuestro header ICMP Echo). De ahi se
 *     recuperan el id y seq que enviamos.
 */
int parse_icmp_reply(const uint8_t *ip_packet, int len,
                     uint16_t *out_id, uint16_t *out_seq);

#endif /* ICMP_H */
