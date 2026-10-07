#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stdint.h>
#include <stddef.h>

/*
 * Crea un RAW socket ICMP con IP_HDRINCL activado, de modo que:
 *   - al ENVIAR, nosotros construimos el header IP completo (incluido el TTL);
 *   - al RECIBIR, el kernel nos entrega todos los paquetes ICMP (Time
 *     Exceeded, Dest Unreachable, Echo Reply) con su header IP incluido.
 *
 * Requiere privilegios de root (sudo).
 * Retorna el file descriptor, o -1 en caso de error.
 *
 * (Adaptado de raw_socket del Laboratorio #05: alli el socket era IPPROTO_TCP;
 *  aqui es IPPROTO_ICMP porque las respuestas de los routers son siempre ICMP.)
 */
int create_raw_socket(void);

/*
 * Envia 'packet' (header IP + ICMP, ya armado y con checksums calculados)
 * de 'packet_len' bytes hacia 'dst_addr' (direccion IPv4 en orden de red).
 * Retorna los bytes enviados, o -1 en error.
 */
int send_packet(int sockfd, const uint8_t *packet, size_t packet_len,
                uint32_t dst_addr);

/*
 * Recibe el proximo paquete IP (header IP incluido) en 'buffer', esperando
 * como maximo 'timeout_ms' milisegundos. Si 'src_addr' no es NULL, guarda
 * ahi la IP de origen (quien respondio) en orden de red.
 * Retorna los bytes recibidos, o -1 si no llego nada a tiempo.
 */
int receive_packet(int sockfd, uint8_t *buffer, size_t buffer_len,
                   int timeout_ms, uint32_t *src_addr);

/* Cierra el socket. */
void close_raw_socket(int sockfd);

#endif /* RAW_SOCKET_H */
