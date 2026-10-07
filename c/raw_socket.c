#include "raw_socket.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int create_raw_socket(void) {
    /* IPPROTO_ICMP: enviamos y recibimos ICMP por el mismo socket. */
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("[raw_socket] Error creando el socket (¿estas corriendo con sudo?)");
        return -1;
    }

    /* IP_HDRINCL: nosotros proveemos el header IP (para fijar el TTL). */
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[raw_socket] Error en setsockopt(IP_HDRINCL)");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int send_packet(int sockfd, const uint8_t *packet, size_t packet_len,
                uint32_t dst_addr) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = dst_addr;

    ssize_t sent = sendto(sockfd, packet, packet_len, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("[raw_socket] Error en sendto");
        return -1;
    }
    return (int)sent;
}

int receive_packet(int sockfd, uint8_t *buffer, size_t buffer_len,
                   int timeout_ms, uint32_t *src_addr) {
    /* El timeout se aplica a ESTA llamada a recvfrom. El bucle superior pasa
     * el tiempo restante para no esperar de mas. */
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    ssize_t received = recvfrom(sockfd, buffer, buffer_len, 0,
                                (struct sockaddr *)&src, &src_len);
    if (received < 0) {
        return -1; /* timeout (EAGAIN/EWOULDBLOCK) u otro error */
    }
    if (src_addr) *src_addr = src.sin_addr.s_addr;
    return (int)received;
}

void close_raw_socket(int sockfd) {
    close(sockfd);
}
