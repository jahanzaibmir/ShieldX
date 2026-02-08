CC=gcc
CFLAGS=-Wall -O2
SRC=src/zx_net_probe.c
OUT=bin/zx_net_probe.exe

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) -lws2_32

clean:
	rm -f bin/*.exe
