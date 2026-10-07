#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Checksum generico "Internet checksum" (RFC 1071).
 * Lo usan tanto el header IP como el header ICMP.
 * 'buffer' debe apuntar a datos de tamanio 'size' en bytes.
 *
 * (Reutilizado del Laboratorio #05; es una libreria auxiliar permitida
 *  por el enunciado para el calculo del checksum.)
 */
uint16_t calculate_checksum(uint16_t *buffer, int size);

#endif /* CHECKSUM_H */
