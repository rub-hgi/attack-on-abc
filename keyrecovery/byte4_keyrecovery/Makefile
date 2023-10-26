.PHONY: all clean
CC = gcc
CFLAGS = -O3 -std=c11

all: byte4 keyrecovery_byte4 stats_differential_attacks_byte4

keyrecovery_byte4: keyrecovery_byte4.o byte4_linker.o
	$(CC) $(CFLAGS) -o keyrecovery_byte4 keyrecovery_byte4.o byte4_linker.o

keyrecovery_byte4.o: keyrecovery_byte4.c byte4.h
	$(CC) $(CFLAGS) -c -o keyrecovery_byte4.o keyrecovery_byte4.c

stats_differential_attacks_byte4: stats_differential_attacks_byte4.o byte4_linker.o
	$(CC) $(CFLAGS) -o stats_differential_attacks_byte4 stats_differential_attacks_byte4.o byte4_linker.o

stats_differential_attacks_byte4.o: stats_differential_attacks_byte4.c
	$(CC) $(CFLAGS) -c -o stats_differential_attacks_byte4.o stats_differential_attacks_byte4.c

byte4_linker.o: byte4_linker.c
	$(CC) $(CFLAGS) -c -o byte4_linker.o byte4_linker.c

byte4.o: byte4.c 
	$(CC) $(CFLAGS) -c -o byte4.o byte4.c

byte4: byte4.o byte4_linker.o
	$(CC) $(CFLAGS) -o byte4 byte4.o byte4_linker.o

clean: 
	rm -f byte4 keyrecovery_byte4 keyrecovery_byte4.o byte4_linker.o byte4 byte4.o stats_differential_attacks_byte4 stats_differential_attacks_byte4.o create_SBox_byte4.sage.py