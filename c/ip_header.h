#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

/*
 * Estructura del header IPv4 (RFC 791), 20 bytes sin opciones.
 * #pragma pack evita que el compilador inserte padding entre campos.
 *
 * (Basado en ip_header del Laboratorio #05. El cambio clave para Traceroute
 *  es que el TTL y el protocolo ahora son PARAMETROS: necesitamos ir
 *  variando el TTL salto a salto, y encapsular ICMP en vez de TCP.)
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  ihl_version;   /* 4 bits version + 4 bits IHL (long. en palabras de 32 bits) */
    uint8_t  tos;           /* Type of Service */
    uint16_t total_length;  /* Longitud total del paquete IP (header + datos), orden de red */
    uint16_t id;            /* Identificador del paquete, usado en fragmentacion */
    uint16_t flags_fo;      /* 3 bits flags + 13 bits fragment offset */
    uint8_t  ttl;           /* Time To Live  <-- la clave de Traceroute */
    uint8_t  protocol;      /* Protocolo encapsulado (1 = ICMP, 6 = TCP, 17 = UDP) */
    uint16_t checksum;      /* Checksum del header IP */
    uint32_t src_addr;      /* IP origen, en orden de red */
    uint32_t dst_addr;      /* IP destino, en orden de red */
} ip_header_t;
#pragma pack(pop)

#define IP_HEADER_LEN sizeof(ip_header_t)

/*
 * Llena 'iph' con los valores de un header IPv4 estandar.
 *   src_ip/dst_ip  : direcciones en texto ("a.b.c.d").
 *   payload_len    : longitud de lo que va DESPUES del header IP (el ICMP).
 *   ttl            : Time To Live a colocar en este paquete.
 *   protocol       : protocolo encapsulado (IPPROTO_ICMP para Traceroute).
 * El checksum se deja en 0; se calcula aparte con checksum.c una vez que el
 * header IP esta completo.
 */
void build_ip_header(ip_header_t *iph, const char *src_ip, const char *dst_ip,
                     uint16_t payload_len, uint8_t ttl, uint8_t protocol);

#endif /* IP_HEADER_H */
