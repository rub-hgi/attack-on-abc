#ifndef BYTE4_H
#define BYTE4_H

#include <stdlib.h>

void die(const char* msg);
u128 random_num(void);
u16 byte4(u16 p, u128 k,int rounds);
u16 byte4_dec(u16 p, u128 k,int rounds);
u32 read_param(char* argv[],int index);
u128 readK(char* arg);

#endif