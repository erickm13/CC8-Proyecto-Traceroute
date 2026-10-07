# Proyecto #02 — Traceroute (Ciencias de la Computación VIII)

Implementación propia de **Traceroute** usando **RAW sockets**, en los tres
lenguajes que pide el enunciado: **C**, **Python** y **Perl**. Las tres versiones
construyen "a mano" el header IP y el header ICMP (no se usa ninguna librería
que genere paquetes, como NetPacket, ni se invoca el comando `traceroute` del
sistema). Como base se reutilizaron los módulos del **Laboratorio #05**
(`checksum`, `ip_header`, `raw_socket`).

## ¿Cómo funciona?

Traceroute aprovecha el campo **TTL** (Time To Live) de la cabecera IP:

1. Se envía un probe **ICMP Echo Request** con `TTL = 1`.
2. El primer router decrementa el TTL a 0, descarta el paquete y responde con
   un **ICMP Time Exceeded** (tipo 11) → así obtenemos la IP del salto 1.
3. Se repite con `TTL = 2, 3, …`, descubriendo un salto por vez.
4. Cuando el probe alcanza el destino, éste responde con un **ICMP Echo Reply**
   (tipo 0) y el recorrido termina.

El emparejamiento probe ↔ respuesta se hace con el `id` (nuestro PID) y el
`seq` (número de secuencia) del ICMP Echo. En las respuestas de error
(Time Exceeded / Dest Unreachable), esos bytes vienen dentro del datagrama
original que el router nos devuelve adjunto al error.

> **Nota sobre el tipo de probe:** usamos **ICMP Echo** (igual que el diagrama
> del enunciado y que `traceroute -I`). El `traceroute` de Linux por defecto usa
> **UDP** a puertos altos; por eso la comparación directa se hace contra
> `traceroute -I`.

## Estructura

```
.
├── c/                  Versión en C (reutiliza módulos del Lab05)
│   ├── checksum.{c,h}      Internet checksum (RFC 1071)
│   ├── ip_header.{c,h}     Construcción del header IPv4 (TTL variable)
│   ├── icmp.{c,h}          Construcción/parseo de ICMP Echo
│   ├── raw_socket.{c,h}    RAW socket ICMP con IP_HDRINCL
│   ├── traceroute.c        Programa principal (loop de TTL)
│   └── Makefile
├── python/traceroute.py    Versión en Python (struct + socket)
├── perl/traceroute.pl      Versión en Perl (pack + Socket)
├── compare.sh              Corre las 3 versiones + traceroute del sistema
├── evidencia/              Logs de comparación generados
└── README.md
```

## Requisitos

- Linux (probado en Arch). Los RAW sockets requieren **root** (`sudo`).
- `gcc` para la versión en C; `python3`; `perl` (con módulos estándar).
- Para la comparación: `traceroute` del sistema
  (`sudo pacman -S traceroute` en Arch / `sudo apt-get install traceroute` en Debian).

## Parámetros (comunes a las tres versiones)

| Opción | Significado                        | Default |
|--------|------------------------------------|---------|
| `-f`   | TTL inicial                        | `1`     |
| `-m`   | Cantidad máxima de saltos          | `64`    |
| `-q`   | Probes enviados por cada salto     | `3`     |
| `-w`   | Timeout por respuesta (segundos)   | `3`     |
| `-z`   | Pausa entre probes (milisegundos)  | `100`   |
| `-n`   | No resolver nombres (solo IPs)     | off     |

El último argumento es el **host o IP destino**.

## Compilar y ejecutar

### C
```bash
cd c
make
sudo ./mitraceroute galileo.edu
sudo ./mitraceroute -n -m 30 -q 3 8.8.8.8
```

### Python
```bash
sudo python3 python/traceroute.py galileo.edu
sudo python3 python/traceroute.py -n -m 30 8.8.8.8
```

### Perl
```bash
sudo perl perl/traceroute.pl galileo.edu
sudo perl perl/traceroute.pl -n -m 30 8.8.8.8
```

## Pruebas / comparación con el sistema

```bash
sudo ./compare.sh 8.8.8.8 20
sudo ./compare.sh galileo.edu
```

Genera `evidencia/comparacion_<host>.log` con la salida de las tres versiones
propias y la de `traceroute -I` del sistema, una tras otra, para compararlas.

### Diferencias esperadas respecto al traceroute del sistema

- **Saltos con `*`:** algunos routers no generan ICMP Time Exceeded (o lo
  limitan por *rate limiting*), por lo que aparecen como `* * *`. Qué routers
  callan puede variar entre ejecuciones y entre nuestra versión y la del
  sistema (cada una envía en instantes distintos).
- **Tiempos (RTT) distintos:** son medidas instantáneas; varían con la carga de
  la red en cada corrida.
- **Rutas ligeramente distintas:** con balanceo de carga (ECMP) el camino puede
  cambiar entre paquetes.
- **UDP vs ICMP:** contra el `traceroute` por defecto (UDP) pueden verse
  diferencias en los últimos saltos / cómo se detecta la llegada al destino; por
  eso comparamos contra `traceroute -I` (modo ICMP), equivalente a nuestro
  enfoque.

## Entregables (según el enunciado)

- [x] Código fuente funcional (C, Python, Perl).
- [x] README con instrucciones de compilación, ejecución y pruebas.
- [x] Script y logs de comparación contra el `traceroute` del sistema.
- [ ] Video con la explicación técnica y la evidencia de pruebas.
