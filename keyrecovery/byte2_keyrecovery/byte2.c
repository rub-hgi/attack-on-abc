/*
    This file implements the B2 (byte 2) cipher. Most of the functions are implemented in byte2_linker,
    this file just makes the execution easier.

    Compile with: make / make byte2
    Run with: ./byte2 <p> <k> <r> [-inv]

    p: the input (maximum 2^16 - 1)
    k: the key (maximum 2^(8*r) - 1)
    r: the number of rounds (usually 8)
    -inv: if set, the inverse / decryption algorithm is run

    The output of this cipher will be printed in stdout (so that it can be used by other programs)
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#include "../../applecipher.h"
#include "byte2.h"


int main(int argc, char* argv[])
{

    u16 p = read_param(argv,1);

    char* end;
    u32 r = strtol(argv[3],&end,16);
    if(strlen(end) != 0) die("r was read wrong\n");

    u128 k = readK(argv[2]);

    u32 c;
    if (argc > 4 && !strcmp(argv[4],"inv")) c = byte2_dec(p,k,r);
    else c = byte2(p,k,r);

    printf("%x\n",c);

    if(byte2_dec(byte2(p,k,r),k,r) == p) return EXIT_SUCCESS;

    perror("Sanitycheck failed\n");
    return EXIT_FAILURE;
}


