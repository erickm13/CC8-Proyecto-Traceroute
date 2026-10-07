#include "checksum.h"

/*
 * Internet checksum (RFC 1071): suma en complemento a uno de palabras de 16
 * bits sobre todo el buffer, con "fold" de los acarreos, y se niega el
 * resultado. Identico al del Laboratorio #05.
 */
uint16_t calculate_checksum(uint16_t *buffer, int size) {
    unsigned long sum = 0;

    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(uint8_t *)buffer; /* ultimo byte impar, si lo hay */
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}
