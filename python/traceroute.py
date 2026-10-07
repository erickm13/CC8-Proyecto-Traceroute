#!/usr/bin/env python3
"""
Traceroute propio en Python usando RAW sockets (Proyecto #02, CC8).

Misma idea que la version en C:
  - Enviamos probes ICMP Echo Request con TTL creciente (1, 2, 3, ...).
  - El router donde el TTL llega a 0 responde ICMP Time Exceeded (tipo 11):
    asi descubrimos ese salto.
  - Cuando el probe llega al destino, este responde ICMP Echo Reply (tipo 0)
    y el recorrido termina.

El header IP y el header ICMP se construyen "a mano" con struct.pack
(no se usa ninguna libreria que genere paquetes). Como auxiliares solo se
usan struct, socket (para el RAW socket y la resolucion de nombres) y time.

Requiere privilegios de root:  sudo python3 traceroute.py <host>
"""

import argparse
import os
import socket
import struct
import sys
import time

ICMP_ECHO_REPLY    = 0
ICMP_DEST_UNREACH  = 3
ICMP_ECHO_REQUEST  = 8
ICMP_TIME_EXCEEDED = 11

ICMP_PAYLOAD = 32  # bytes de datos dentro del ICMP Echo

# Valores por defecto exigidos por el enunciado.
DEF_FIRST_TTL  = 1
DEF_MAX_HOPS   = 64
DEF_QUERIES    = 3
DEF_TIMEOUT_S  = 3.0    # 3 segundos
DEF_PAUSE_MS   = 100    # 100 ms entre probes


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) sobre 'data'."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_icmp_echo(ident: int, seq: int, payload_len: int) -> bytes:
    """Arma un ICMP Echo Request (header + datos) con su checksum."""
    payload = bytes((0x40 + (i & 0x3F)) for i in range(payload_len))
    # checksum=0 para el primer calculo
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chk = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chk, ident, seq)
    return header + payload


def build_ip_header(src_ip: str, dst_ip: str, payload_len: int, ttl: int) -> bytes:
    """Arma un header IPv4 de 20 bytes con el TTL indicado y protocolo ICMP."""
    version_ihl = (4 << 4) | 5            # version 4, IHL 5 (20 bytes)
    tos         = 0
    total_len   = 20 + payload_len
    packet_id   = 54321
    flags_fo    = 0x4000                  # Don't Fragment
    proto       = socket.IPPROTO_ICMP     # 1
    checksum0   = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header = struct.pack("!BBHHHBBH4s4s",
                         version_ihl, tos, total_len, packet_id,
                         flags_fo, ttl, proto, checksum0, src, dst)
    chk = checksum(header)
    header = struct.pack("!BBHHHBBH4s4s",
                         version_ihl, tos, total_len, packet_id,
                         flags_fo, ttl, proto, chk, src, dst)
    return header


def parse_icmp_reply(pkt: bytes, want_id: int, want_seq: int):
    """Devuelve el tipo ICMP (0/3/11) si 'pkt' es respuesta a nuestro probe
    con (want_id, want_seq); si no, devuelve None."""
    if len(pkt) < 20:
        return None
    ip_ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ip_ihl + 8:
        return None

    icmp_type = pkt[ip_ihl]

    if icmp_type == ICMP_ECHO_REPLY:
        _, _, _, rid, rseq = struct.unpack("!BBHHH", pkt[ip_ihl:ip_ihl + 8])
        if rid == want_id and rseq == want_seq:
            return ICMP_ECHO_REPLY
        return None

    if icmp_type in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH):
        inner = pkt[ip_ihl + 8:]          # IP original + 8 bytes (nuestro Echo)
        if len(inner) < 20:
            return None
        inner_ihl = (inner[0] & 0x0F) * 4
        if len(inner) < inner_ihl + 8:
            return None
        _, _, _, rid, rseq = struct.unpack("!BBHHH", inner[inner_ihl:inner_ihl + 8])
        if rid == want_id and rseq == want_seq:
            return icmp_type
        return None

    return None


def get_local_ip(dst_ip: str) -> str:
    """IP local que el kernel usaria para alcanzar dst_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 53))
        return s.getsockname()[0]
    finally:
        s.close()


def resolve_name(ip: str, numeric: bool) -> str:
    if numeric:
        return ip
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ip


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Traceroute propio con RAW sockets (ICMP).")
    ap.add_argument("host", help="host o IP destino")
    ap.add_argument("-f", type=int, default=DEF_FIRST_TTL, help="TTL inicial [1]")
    ap.add_argument("-m", type=int, default=DEF_MAX_HOPS, help="maximo de saltos [64]")
    ap.add_argument("-q", type=int, default=DEF_QUERIES, help="probes por salto [3]")
    ap.add_argument("-w", type=float, default=DEF_TIMEOUT_S, help="timeout en seg [3]")
    ap.add_argument("-z", type=int, default=DEF_PAUSE_MS, help="pausa entre probes en ms [100]")
    ap.add_argument("-n", action="store_true", help="no resolver nombres (solo IPs)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Aviso: los RAW sockets requieren root. Ejecuta con sudo.",
              file=sys.stderr)

    try:
        dst_ip = socket.gethostbyname(args.host)
    except OSError:
        print(f"No se pudo resolver '{args.host}'.", file=sys.stderr)
        return 1

    src_ip = get_local_ip(dst_ip)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("Permiso denegado: ejecuta con sudo.", file=sys.stderr)
        return 1

    total_bytes = 20 + 8 + ICMP_PAYLOAD
    print(f"traceroute to {args.host} ({dst_ip}), {args.m} hops max, "
          f"{total_bytes} byte packets")

    ident = os.getpid() & 0xFFFF
    seq = 0
    reached = False
    ttl = args.f

    while ttl <= args.m and not reached:
        print(f"{ttl:2d} ", end="", flush=True)
        last_addr = None

        for p in range(args.q):
            seq += 1
            packet = (build_ip_header(src_ip, dst_ip, 8 + ICMP_PAYLOAD, ttl)
                      + build_icmp_echo(ident, seq, ICMP_PAYLOAD))

            t0 = time.monotonic()
            sock.sendto(packet, (dst_ip, 0))

            deadline = t0 + args.w
            got = False
            rtype = None
            from_ip = None

            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    break
                sock.settimeout(remain)
                try:
                    data, addr = sock.recvfrom(1500)
                except socket.timeout:
                    break
                t = parse_icmp_reply(data, ident, seq)
                if t is None:
                    continue
                from_ip = addr[0]
                rtype = t
                got = True
                break

            rtt = (time.monotonic() - t0) * 1000.0

            if not got:
                print(" *", end="", flush=True)
            else:
                if from_ip != last_addr:
                    if args.n:
                        print(f" {from_ip}", end="")
                    else:
                        print(f" {resolve_name(from_ip, False)} ({from_ip})", end="")
                    last_addr = from_ip
                print(f"  {rtt:.3f} ms", end="", flush=True)

                if from_ip == dst_ip and rtype in (ICMP_ECHO_REPLY, ICMP_DEST_UNREACH):
                    reached = True

            if p < args.q - 1 and args.z > 0:
                time.sleep(args.z / 1000.0)

        print()
        ttl += 1

    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
