#ifndef BYTE2_H
#define BYTE2_H

#include <stdlib.h>

void die(const char* msg);
u128 random_num(void);
u16 byte2(u16 p, u128 k,int rounds);
u16 byte2_dec(u16 p, u128 k,int rounds);
u32 read_param(char* argv[],int index);
u128 readK(char* arg);

#endif