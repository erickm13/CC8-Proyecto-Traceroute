#!/usr/bin/env bash
#
# compare.sh - Ejecuta las tres implementaciones propias de Traceroute y el
# traceroute del sistema contra un mismo destino, guardando la evidencia en
# evidencia/comparacion_<host>.log (requerido por el enunciado).
#
# Uso:  sudo ./compare.sh <host> [max_hops]
# Ej.:  sudo ./compare.sh 8.8.8.8 20
#       sudo ./compare.sh galileo.edu

set -u
HOST="${1:-galileo.edu}"
MAXH="${2:-20}"

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/evidencia"
mkdir -p "$OUT"
LOG="$OUT/comparacion_${HOST}.log"

if [ "$(id -u)" -ne 0 ]; then
    echo "Este script usa RAW sockets: ejecutalo con sudo." >&2
    exit 1
fi

# Compila la version en C si hace falta.
if [ ! -x "$DIR/c/mitraceroute" ]; then
    echo "Compilando la version en C..."
    make -C "$DIR/c"
fi

run() {
    echo "===== $1 ====="
    shift
    "$@"
    echo
}

{
    echo "Comparacion Traceroute - destino: $HOST (max $MAXH saltos)"
    echo "Fecha: $(date)"
    echo
    run "mitraceroute (C)"        "$DIR/c/mitraceroute"  -n -m "$MAXH" "$HOST"
    run "traceroute.py (Python)"  python3 "$DIR/python/traceroute.py" -n -m "$MAXH" "$HOST"
    run "traceroute.pl (Perl)"    perl "$DIR/perl/traceroute.pl" -n -m "$MAXH" "$HOST"

    if command -v traceroute >/dev/null 2>&1; then
        run "traceroute -I (sistema)" traceroute -I -n -m "$MAXH" "$HOST"
    else
        echo "===== traceroute del sistema no instalado ====="
        echo "Instalalo con:  sudo pacman -S traceroute   (Arch)"
        echo "            o:  sudo apt-get install traceroute (Debian/Ubuntu)"
    fi
} | tee "$LOG"

echo
echo "Evidencia guardada en: $LOG"
