# Makefile - Proyecto #02 Traceroute (version en C)
# --------------------------------------------------
#   make          -> compila el binario ./mitraceroute
#   make run      -> ejecuta con sudo contra HOST (por defecto galileo.edu)
#   make clean    -> elimina binario y objetos
#
# Se puede pasar el destino y argumentos con HOST y ARGS, por ejemplo:
#   make run HOST=8.8.8.8 ARGS="-q 3 -m 30"

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE

TARGET  = mitraceroute
OBJS    = traceroute.o icmp.o ip_header.o checksum.o raw_socket.o

HOST ?= galileo.edu
ARGS ?=

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Cada .o depende de los headers comunes
%.o: %.c icmp.h ip_header.h checksum.h raw_socket.h
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	sudo ./$(TARGET) $(ARGS) $(HOST)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all run clean
