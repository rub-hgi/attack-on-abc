.PHONY: all clean other
CC = g++
CFLAGS = -O3 -std=c++17

all: armamatrix mitm other

other: 
	cd keyrecovery/byte2_keyrecovery && make
	cd keyrecovery/byte4_keyrecovery && make
	cd keyrecovery/keyschedule && make

armamatrix: armamatrix.cpp
	$(CC) $(CFLAGS) -o armamatrix -larmadillo armamatrix.cpp

mitm: abc.cpp
	$(CC) -Ofast -std=c++14 -march=native -Wall -Wextra -Wpedantic abc.cpp -o mitm

clean: 
	rm -f armamatrix mitm 
	cd keyrecovery/byte2_keyrecovery && make clean
	cd keyrecovery/byte4_keyrecovery && make clean
	cd keyrecovery/keyschedule && make clean