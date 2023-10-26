.PHONY: all clean
CC = gcc
CFLAGS = -O3 -std=c11

all: byte2 keyrecovery_byte2 stats_differential_attacks_byte2

keyrecovery_byte2: keyrecovery_byte2.o byte2_linker.o
	$(CC) $(CFLAGS) -o keyrecovery_byte2 keyrecovery_byte2.o byte2_linker.o

keyrecovery_byte2.o: keyrecovery_byte2.c
	$(CC) $(CFLAGS) -c -o keyrecovery_byte2.o keyrecovery_byte2.c

stats_differential_attacks_byte2: stats_differential_attacks_byte2.o byte2_linker.o
	$(CC) $(CFLAGS) -o stats_differential_attacks_byte2 stats_differential_attacks_byte2.o byte2_linker.o

stats_differential_attacks_byte2.o: stats_differential_attacks_byte2.c
	$(CC) $(CFLAGS) -c -o stats_differential_attacks_byte2.o stats_differential_attacks_byte2.c

byte2_linker.o: byte2_linker.c
	$(CC) $(CFLAGS) -c -o byte2_linker.o byte2_linker.c

byte2.o:
	$(CC) $(CFLAGS) byte2.c -c -o byte2.o

byte2: byte2.o byte2_linker.o
	$(CC) $(CFLAGS) byte2.o byte2_linker.o -o byte2

clean: 
	rm -f byte2 byte2.o keyrecovery_byte2 keyrecovery_byte2.o byte2_linker.o byte2 stats_differential_attacks_byte2 stats_differential_attacks_byte2.o create_SBox_byte2.sage.py