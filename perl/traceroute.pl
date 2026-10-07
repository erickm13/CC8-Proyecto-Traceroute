#!/usr/bin/env perl
#
# Traceroute propio en Perl usando RAW sockets (Proyecto #02, CC8).
#
# Misma idea que las versiones en C y Python:
#   - Enviamos probes ICMP Echo Request con TTL creciente (1, 2, 3, ...).
#   - El router donde el TTL llega a 0 responde ICMP Time Exceeded (tipo 11):
#     asi descubrimos ese salto.
#   - Cuando el probe llega al destino, este responde ICMP Echo Reply (tipo 0)
#     y el recorrido termina.
#
# El header IP y el header ICMP se construyen "a mano" con pack(). Solo se usan
# modulos estandar auxiliares: Socket (RAW socket y resolucion de nombres),
# Getopt::Long (argumentos) y Time::HiRes (tiempos).
#
# Requiere privilegios de root:  sudo perl traceroute.pl <host>

use strict;
use warnings;
use Socket;
use Getopt::Long;
use Time::HiRes qw(time sleep);

# Constantes ICMP (RFC 792).
use constant {
    ICMP_ECHO_REPLY    => 0,
    ICMP_DEST_UNREACH  => 3,
    ICMP_ECHO_REQUEST  => 8,
    ICMP_TIME_EXCEEDED => 11,
};

# Constantes de socket a nivel IP (valores de Linux).
use constant {
    PROTO_ICMP => 1,
    LVL_IP     => 0,    # IPPROTO_IP
    IP_HDRINCL => 3,    # en Linux
};

use constant ICMP_PAYLOAD => 32;    # bytes de datos dentro del ICMP Echo

# --- Valores por defecto exigidos por el enunciado ---
my $first_ttl = 1;
my $max_hops  = 64;
my $queries   = 3;
my $timeout_s = 3;      # 3 segundos
my $pause_ms  = 100;    # 100 ms entre probes
my $numeric   = 0;

GetOptions(
    "f=i" => \$first_ttl,
    "m=i" => \$max_hops,
    "q=i" => \$queries,
    "w=f" => \$timeout_s,
    "z=i" => \$pause_ms,
    "n"   => \$numeric,
) or die "Argumentos invalidos\n";

my $host = shift @ARGV or die "Uso: sudo perl traceroute.pl [opciones] <host>\n";

# Internet checksum (RFC 1071) sobre una cadena de bytes.
sub checksum {
    my ($data) = @_;
    $data .= "\x00" if length($data) % 2;    # padding a 16 bits
    my $sum = 0;
    foreach my $word (unpack("n*", $data)) {
        $sum += $word;
    }
    $sum = ($sum & 0xFFFF) + ($sum >> 16) while $sum >> 16;
    return (~$sum) & 0xFFFF;
}

# Arma un ICMP Echo Request (header + datos) con su checksum.
sub build_icmp_echo {
    my ($id, $seq) = @_;
    my $payload = join("", map { chr(0x40 + ($_ & 0x3F)) } 0 .. ICMP_PAYLOAD - 1);
    my $hdr = pack("C C n n n", ICMP_ECHO_REQUEST, 0, 0, $id, $seq);
    my $chk = checksum($hdr . $payload);
    $hdr = pack("C C n n n", ICMP_ECHO_REQUEST, 0, $chk, $id, $seq);
    return $hdr . $payload;
}

# Arma un header IPv4 de 20 bytes con el TTL indicado y protocolo ICMP.
sub build_ip_header {
    my ($src_ip, $dst_ip, $payload_len, $ttl) = @_;
    my $ver_ihl   = (4 << 4) | 5;        # version 4, IHL 5 (20 bytes)
    my $tos       = 0;
    my $total_len = 20 + $payload_len;
    my $id        = 54321;
    my $flags_fo  = 0x4000;              # Don't Fragment
    my $proto     = PROTO_ICMP;
    my $src       = inet_aton($src_ip);
    my $dst       = inet_aton($dst_ip);

    my $hdr = pack("C C n n n C C n a4 a4",
                   $ver_ihl, $tos, $total_len, $id, $flags_fo,
                   $ttl, $proto, 0, $src, $dst);
    my $chk = checksum($hdr);
    $hdr = pack("C C n n n C C n a4 a4",
                $ver_ihl, $tos, $total_len, $id, $flags_fo,
                $ttl, $proto, $chk, $src, $dst);
    return $hdr;
}

# Analiza un paquete recibido. Devuelve el tipo ICMP (0/3/11) si corresponde a
# nuestro probe (mismo id y seq); si no, devuelve undef.
sub parse_icmp_reply {
    my ($pkt, $want_id, $want_seq) = @_;
    return undef if length($pkt) < 20;

    my $ip_ihl = (unpack("C", substr($pkt, 0, 1)) & 0x0F) * 4;
    return undef if length($pkt) < $ip_ihl + 8;

    my $type = unpack("C", substr($pkt, $ip_ihl, 1));

    if ($type == ICMP_ECHO_REPLY) {
        my ($t, $c, $ck, $rid, $rseq) = unpack("C C n n n", substr($pkt, $ip_ihl, 8));
        return ($rid == $want_id && $rseq == $want_seq) ? ICMP_ECHO_REPLY : undef;
    }

    if ($type == ICMP_TIME_EXCEEDED || $type == ICMP_DEST_UNREACH) {
        my $inner = substr($pkt, $ip_ihl + 8);    # IP original + 8 bytes (Echo)
        return undef if length($inner) < 20;
        my $inner_ihl = (unpack("C", substr($inner, 0, 1)) & 0x0F) * 4;
        return undef if length($inner) < $inner_ihl + 8;
        my ($t, $c, $ck, $rid, $rseq) =
            unpack("C C n n n", substr($inner, $inner_ihl, 8));
        return ($rid == $want_id && $rseq == $want_seq) ? $type : undef;
    }

    return undef;
}

# IP local que el kernel usaria para alcanzar $dst_ip.
sub get_local_ip {
    my ($dst_ip) = @_;
    socket(my $u, PF_INET, SOCK_DGRAM, 0) or return "0.0.0.0";
    connect($u, sockaddr_in(53, inet_aton($dst_ip))) or return "0.0.0.0";
    my ($port, $addr) = sockaddr_in(getsockname($u));
    close($u);
    return inet_ntoa($addr);
}

sub resolve_name {
    my ($ip, $num) = @_;
    return $ip if $num;
    my $name = gethostbyaddr(inet_aton($ip), AF_INET);
    return $name ? $name : $ip;
}

# ----------------------------- Programa principal --------------------------
warn "Aviso: los RAW sockets requieren root. Ejecuta con sudo.\n" if $> != 0;

my $dst_packed = inet_aton($host) or die "No se pudo resolver '$host'.\n";
my $dst_ip = inet_ntoa($dst_packed);
my $src_ip = get_local_ip($dst_ip);

socket(my $sock, PF_INET, SOCK_RAW, PROTO_ICMP)
    or die "No se pudo crear el RAW socket (¿sudo?): $!\n";
setsockopt($sock, LVL_IP, IP_HDRINCL, 1)
    or die "No se pudo activar IP_HDRINCL: $!\n";

my $total_bytes = 20 + 8 + ICMP_PAYLOAD;
printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
       $host, $dst_ip, $max_hops, $total_bytes);

my $id      = $$ & 0xFFFF;    # PID como identificador
my $seq     = 0;
my $reached = 0;
my $dest    = sockaddr_in(0, $dst_packed);

for (my $ttl = $first_ttl; $ttl <= $max_hops && !$reached; $ttl++) {
    printf("%2d ", $ttl);
    $| = 1;    # autoflush
    my $last_addr = "";

    for (my $p = 0; $p < $queries; $p++) {
        $seq++;
        my $packet = build_ip_header($src_ip, $dst_ip, 8 + ICMP_PAYLOAD, $ttl)
                   . build_icmp_echo($id, $seq);

        my $t0 = time();
        send($sock, $packet, 0, $dest);

        my $deadline = $t0 + $timeout_s;
        my ($got, $rtype, $from_ip) = (0, undef, undef);

        while (1) {
            my $remain = $deadline - time();
            last if $remain <= 0;

            my $rin = '';
            vec($rin, fileno($sock), 1) = 1;
            my $nfound = select(my $rout = $rin, undef, undef, $remain);
            last if $nfound == 0;    # timeout

            my $buf;
            my $paddr = recv($sock, $buf, 1500, 0);
            next unless defined $paddr;

            my $t = parse_icmp_reply($buf, $id, $seq);
            next unless defined $t;

            my ($port, $addr) = sockaddr_in($paddr);
            $from_ip = inet_ntoa($addr);
            $rtype   = $t;
            $got     = 1;
            last;
        }

        my $rtt = (time() - $t0) * 1000.0;

        if (!$got) {
            print " *";
        } else {
            if ($from_ip ne $last_addr) {
                if ($numeric) {
                    print " $from_ip";
                } else {
                    my $name = resolve_name($from_ip, 0);
                    print " $name ($from_ip)";
                }
                $last_addr = $from_ip;
            }
            printf("  %.3f ms", $rtt);

            $reached = 1
                if $from_ip eq $dst_ip
                && ($rtype == ICMP_ECHO_REPLY || $rtype == ICMP_DEST_UNREACH);
        }
        $| = 1;

        sleep($pause_ms / 1000.0) if $p < $queries - 1 && $pause_ms > 0;
    }
    print "\n";
}

close($sock);
