/* traceroute.c
 * ------------
 * Implementacion propia de Traceroute usando RAW sockets (Proyecto #02, CC8).
 *
 * Idea (ver el PDF del enunciado):
 *   - Se envian probes ICMP Echo Request con un TTL que crece de 1 en 1.
 *   - El router donde el TTL llega a 0 descarta el paquete y responde con un
 *     ICMP Time Exceeded (tipo 11): asi descubrimos ese salto.
 *   - Cuando el probe finalmente alcanza el destino, este responde con un
 *     ICMP Echo Reply (tipo 0) y el recorrido termina.
 *
 * Todo el header IP y el header ICMP se construyen "a mano" (ver ip_header.c
 * e icmp.c). Como libreria auxiliar usamos solo el calculo de checksum y la
 * resolucion de nombres (getaddrinfo/getnameinfo), permitidas por el enunciado.
 */
#include "ip_header.h"
#include "icmp.h"
#include "raw_socket.h"
#include "checksum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PACKET_BUF   1500
#define ICMP_PAYLOAD 32      /* bytes de datos dentro del ICMP Echo */

/* Valores por defecto exigidos por el enunciado. */
#define DEF_FIRST_TTL   1
#define DEF_MAX_HOPS   64
#define DEF_QUERIES     3
#define DEF_TIMEOUT_MS 3000  /* 3 segundos */
#define DEF_PAUSE_MS    100  /* 100 ms entre probes */

typedef struct {
    int         first_ttl;   /* TTL inicial                           */
    int         max_hops;    /* cantidad maxima de saltos             */
    int         queries;     /* probes por salto                      */
    int         timeout_ms;  /* espera por respuesta de cada probe    */
    int         pause_ms;    /* pausa entre probes                    */
    int         numeric;     /* 1 = no resolver nombres (como -n)     */
    const char *target;      /* host o IP destino                     */
} config_t;

/* Reloj monotono en milisegundos (para medir RTT y timeouts). */
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* Averigua la IP local que el kernel usaria para alcanzar 'dst_addr'.
 * Truco clasico: "conectar" un socket UDP (no envia nada) y leer getsockname. */
static int get_local_ip(uint32_t dst_addr, char *out, size_t n) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in d;
    memset(&d, 0, sizeof(d));
    d.sin_family      = AF_INET;
    d.sin_addr.s_addr = dst_addr;
    d.sin_port        = htons(53);
    if (connect(s, (struct sockaddr *)&d, sizeof(d)) < 0) { close(s); return -1; }

    struct sockaddr_in local;
    socklen_t ll = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &ll) < 0) { close(s); return -1; }

    inet_ntop(AF_INET, &local.sin_addr, out, n);
    close(s);
    return 0;
}

/* Resuelve el nombre (DNS inverso) de 'addr'. Si numeric=1 o falla, deja la
 * IP en texto. */
static void resolve_name(uint32_t addr, char *out, size_t n, int numeric) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = addr;

    if (numeric ||
        getnameinfo((struct sockaddr *)&sa, sizeof(sa), out, n, NULL, 0,
                    NI_NAMEREQD) != 0) {
        inet_ntop(AF_INET, &sa.sin_addr, out, n);
    }
}

static void print_help(const char *prog) {
    printf(
    "Uso: sudo %s [opciones] <host|IP>\n"
    "  -f <ttl>      TTL inicial.                         [def: %d]\n"
    "  -m <saltos>   Cantidad maxima de saltos.           [def: %d]\n"
    "  -q <n>        Probes enviados por cada salto.       [def: %d]\n"
    "  -w <seg>      Timeout por respuesta, en segundos.   [def: %d]\n"
    "  -z <ms>       Pausa entre probes, en milisegundos.  [def: %d]\n"
    "  -n            No resolver nombres (solo IPs).\n"
    "  -h            Muestra esta ayuda.\n"
    "\nEjemplo:  sudo %s -q 3 -m 30 galileo.edu\n",
    prog, DEF_FIRST_TTL, DEF_MAX_HOPS, DEF_QUERIES,
    DEF_TIMEOUT_MS / 1000, DEF_PAUSE_MS, prog);
}

int main(int argc, char **argv) {
    config_t cfg;
    cfg.first_ttl  = DEF_FIRST_TTL;
    cfg.max_hops   = DEF_MAX_HOPS;
    cfg.queries    = DEF_QUERIES;
    cfg.timeout_ms = DEF_TIMEOUT_MS;
    cfg.pause_ms   = DEF_PAUSE_MS;
    cfg.numeric    = 0;
    cfg.target     = NULL;

    /* --- Parseo de argumentos --- */
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-h")) { print_help(argv[0]); return 0; }
        else if (!strcmp(argv[i], "-n")) { cfg.numeric = 1; }
        else if (!strcmp(argv[i], "-f") && i + 1 < argc) cfg.first_ttl  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-m") && i + 1 < argc) cfg.max_hops   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-q") && i + 1 < argc) cfg.queries    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) cfg.timeout_ms = (int)(atof(argv[++i]) * 1000);
        else if (!strcmp(argv[i], "-z") && i + 1 < argc) cfg.pause_ms   = atoi(argv[++i]);
        else if (argv[i][0] != '-')      cfg.target = argv[i];
        else { fprintf(stderr, "Argumento desconocido: %s\n", argv[i]); print_help(argv[0]); return 1; }
    }

    if (!cfg.target) {
        fprintf(stderr, "Falta el host destino.\n");
        print_help(argv[0]);
        return 1;
    }
    if (cfg.first_ttl < 1 || cfg.first_ttl > cfg.max_hops) {
        fprintf(stderr, "TTL inicial invalido (debe estar entre 1 y max_hops).\n");
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Aviso: los RAW sockets requieren privilegios de root. "
                        "Ejecuta con sudo.\n");
    }

    /* --- Resolver el destino (DNS) --- */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(cfg.target, NULL, &hints, &res) != 0 || !res) {
        fprintf(stderr, "No se pudo resolver '%s'.\n", cfg.target);
        return 1;
    }
    uint32_t dst_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    char src_ip[INET_ADDRSTRLEN];
    if (get_local_ip(dst_addr, src_ip, sizeof(src_ip)) != 0) {
        fprintf(stderr, "No se pudo determinar la IP local de salida.\n");
        return 1;
    }

    /* --- Crear el RAW socket --- */
    int sockfd = create_raw_socket();
    if (sockfd < 0) return 1;

    printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
           cfg.target, dst_ip, cfg.max_hops,
           (int)(IP_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD));

    uint16_t id   = (uint16_t)(getpid() & 0xFFFF); /* nos identifica a nosotros */
    uint16_t seq  = 0;
    int reached   = 0;

    /* ------------------------- Bucle principal por salto ------------------- */
    for (int ttl = cfg.first_ttl; ttl <= cfg.max_hops && !reached; ttl++) {
        printf("%2d ", ttl);
        fflush(stdout);

        uint32_t last_addr = 0;
        int      have_last = 0;

        for (int p = 0; p < cfg.queries; p++) {
            seq++;

            /* --- Armar el paquete: header IP + ICMP Echo --- */
            uint8_t packet[PACKET_BUF];
            memset(packet, 0, sizeof(packet));

            int icmp_len = build_icmp_echo(packet + IP_HEADER_LEN, id, seq, ICMP_PAYLOAD);

            ip_header_t *iph = (ip_header_t *)packet;
            build_ip_header(iph, src_ip, dst_ip, (uint16_t)icmp_len,
                            (uint8_t)ttl, IPPROTO_ICMP);
            iph->checksum = calculate_checksum((uint16_t *)packet, IP_HEADER_LEN);

            int total = (int)IP_HEADER_LEN + icmp_len;

            /* --- Enviar y esperar la respuesta que corresponde a ESTE probe --- */
            double t0 = now_ms();
            send_packet(sockfd, packet, total, dst_addr);

            double   deadline = t0 + cfg.timeout_ms;
            int      got = 0, type = -1;
            uint32_t from = 0;

            while (1) {
                double remain = deadline - now_ms();
                if (remain <= 0) break;

                uint8_t  rbuf[PACKET_BUF];
                uint32_t rsrc = 0;
                int rlen = receive_packet(sockfd, rbuf, sizeof(rbuf),
                                          (int)remain, &rsrc);
                if (rlen < 0) break; /* timeout */

                uint16_t rid, rseq;
                int t = parse_icmp_reply(rbuf, rlen, &rid, &rseq);
                if (t < 0) continue;                 /* ICMP ajeno            */
                if (rid != id || rseq != seq) continue; /* no es nuestro probe */

                from = rsrc; type = t; got = 1;
                break;
            }
            double rtt = now_ms() - t0;

            /* --- Imprimir el resultado de este probe --- */
            if (!got) {
                printf(" *");
            } else {
                if (!have_last || from != last_addr) {
                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &from, ipstr, sizeof(ipstr));
                    if (cfg.numeric) {
                        printf(" %s", ipstr);
                    } else {
                        char name[NI_MAXHOST];
                        resolve_name(from, name, sizeof(name), 0);
                        printf(" %s (%s)", name, ipstr);
                    }
                    last_addr = from;
                    have_last = 1;
                }
                printf("  %.3f ms", rtt);

                /* Llegamos al destino: Echo Reply, o un Dest Unreachable
                 * generado por el propio destino. */
                if (from == dst_addr &&
                    (type == ICMP_ECHO_REPLY || type == ICMP_DEST_UNREACH)) {
                    reached = 1;
                }
            }
            fflush(stdout);

            if (p < cfg.queries - 1 && cfg.pause_ms > 0)
                usleep(cfg.pause_ms * 1000);
        }
        printf("\n");
    }

    close_raw_socket(sockfd);
    return 0;
}
