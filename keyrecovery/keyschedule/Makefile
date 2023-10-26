.PHONY: all clean
all: mkrecovery abc_linker.o
CC = g++
CFLAGS = -Ofast -march=native -Wall -Wextra -Wpedantic -std=c++14

mkrecovery: mkrecovery.o abc_linker.o
	$(CC) $(CFLAGS) mkrecovery.o abc_linker.o -o mkrecovery

mkrecovery.o: masterkeyrecovery.cpp
	$(CC) $(CFLAGS) masterkeyrecovery.cpp -c -o mkrecovery.o

abc_linker.o:
	$(CC) $(CFLAGS) abc_linker.cpp -c -o abc_linker.o

clean:
	rm -f mkrecovery mkrecovery.o abc_linker.o dependency_test.sage.py greedy_easiestbruteforce_algorithm.sage.py