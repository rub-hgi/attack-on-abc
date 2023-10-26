/*
    This file is not executable and only is used to incorporate the cipher-functions in the attack-files.
*/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h> 

#include "../../applecipher.h"
#include "byte4.h"


void die(const char* msg) 
{
    perror(msg);
    exit(EXIT_FAILURE);
}

u128 random_num(void) 
{
    u128 rnd;
    if(getentropy(&rnd,16)) die("random_num");
    return rnd;
}

state64 xor64(state64 a, state64 b)
{
    state64 res;
    for (int i = 0; i < 8; i++) 
        res.data[i] = a.data[i] ^ b.data[i];
    return res;
}

state128 xor128(state128 a, state128 b)
{
    state128 res;
    for (int i = 0; i < 16; i++)
        res.data[i] = a.data[i] ^ b.data[i];
    return res;
}

#define xor(x, y) _Generic((x), state64: xor64, state128: xor128)(x, y)

int S(int i,bool inv)
{
    if (inv)
    {
        int S_arr[16] = {2, 6, 10, 14, 0, 11, 4, 15, 3, 8, 12, 7, 1, 9, 5, 13};
        return S_arr[i];
    }
    else
    {
        int S_arr[16] = {4, 12, 0, 8, 6, 14, 1, 11, 9, 13, 2, 5, 10, 15, 3, 7};
        return S_arr[i];
    }
}

state64 sLayer(state64 input,bool inv)
{
    state64 out;
    for (int i = 0;i<8;i++)
    {
        if (inv)
            out.data[i] = S(input.data[i]/16,true)*16 + S(input.data[i]%16,true);
        else
            out.data[i] = S(input.data[i]/16,false)*16 + S(input.data[i]%16,false);
    }
    return out;
}

state64 r(state64 input,bool inv)
{
    state64 out;
    for (int i = 0;i < 8;i++)
    {
        if (inv)
            out.data[i] = (input.data[i] >> i) + ((input.data[i] << (8-i)) & 0xff);
        else
            out.data[i] = ((input.data[i] << i) & 0xff) + (input.data[i] >> (8-i));
    }
    return out;
}

state64 bigR(state64 input)
{
    state64 out;
    int R[8] = {6,5,2,7,4,1,0,3};
    for (int i = 0; i < 8;i++)
        out.data[i] = input.data[R[i]];

    return out;
}

state64 bs(state64 input,bool inv)
{
    state64 out;
    if (inv)
        for (int i = 0; i < 8;i++)
            out.data[i] = (171 * input.data[i] + 119) % 256;
    else
        for (int i = 0; i < 8;i++)
            out.data[i] = (3 * input.data[i] + 155) % 256;

    return out;
}

state64 rotateXOR(state64 input,int round)
{
    state64 out;
    u32 left = 0;
    u32 right = 0; 
    for (int i = 0; i < 4; i++)
    {
        left += input.data[i] * 1<<(8*(3-i));
        right += input.data[i+4] * 1<<(8*(3-i));
    }

    u32 new_left,new_right;
    if (13+round == 32)
    {
        new_left = left;
        new_right = (right << (29+round)) + (right >> (32-(29+round)));
    }
    if (29+round == 32)
    {
        new_left = (left << (13+round)) + (left >> (32-(13+round)));
        new_right = right;
    }
    else
    {
        new_left = (left << (13+round)) + (left >> (32-(13+round)));
        new_right = (right << (29+round)) + (right >> (32-(29+round)));
    }

    for (int i = 0; i < 4; i++)
    {
        out.data[i] = ((u8) (new_left/(1<<(8*(3-i)))));
        out.data[i+4] = ((u8) (new_right/(1<<(8*(3-i)))));
    }
    return xor(out,input);
}

state128 runde(state128 input,state64 key,bool inv)
{
    state64 left,right,out_right;
    state128 out;
    for (int i = 0; i < 8;i++)
    {
        left.data[i] = input.data[i];
        right.data[i] = input.data[i+8];
    }
    if (!inv)
    {
        out_right = bs(xor(bigR(left),r(sLayer(xor(right,key),false),false)),false);
        
        for (int i = 0; i < 8; i++)
        {
            out.data[i] = right.data[i];
            out.data[i+8] = out_right.data[i];
        }
    }
    else
    {
        out_right = bigR(xor(r(sLayer(xor(left,key),false),false),bs(right,true)));
        for (int i = 0; i < 8; i++)
        {
            out.data[i] = out_right.data[i];
            out.data[i+8] = left.data[i];
        }
    }
    return out;
}


u16 byte4(u16 p, u128 k,int rounds)
{
    state128 state = {0,0,0,0,(p>>8) & 0xff,0,0,0,0,0,0,0,p & 0xff,0,0,0};
    for (int i = (rounds-1); i >= 0;i--)
    {
        state64 _k = {0,0,0,0,(k>>(8*i)) & 0xff,0,0,0}; // state64 ist hier ein struct uint8[8], jeder Eintrag ist mod 256 
        state = runde(state,_k,false);
    }
    u16 output = state.data[4] * (1<<8) + state.data[12];
    return output;
}

u16 byte4_dec(u16 p, u128 k,int rounds)
{
    state128 state = {0,0,0,0,(p>>8) & 0xff,0,0,0,0,0,0,0,p & 0xff,0,0,0};
    for (int i = 0; i < rounds;i++)
    {
        state64 _k = {0,0,0,0,(k>>(8*i)) & 0xff,0,0,0}; // state64 ist hier ein struct uint8[8], jeder Eintrag ist mod 256 
        state = runde(state,_k,true);
    }
    u16 output = state.data[4] * (1<<8) + state.data[12];
    return output;
}


u32 read_param(char* argv[],int index)
{
    u32 p = 0;
    int i = 0;
    while(argv[index][i]) i++;
    if(i>4 && index == 1) die("p too long");
    if(i>16 && index == 2) die("k too long");
    if(i>1 && index == 3) die("rounds too long, maximum 16 rounds");
    i--;
    int j = i;
    while(argv[index][i] && i >= 0)
    {
        if(argv[index][i] >= 0x30 && argv[index][i] <= 0x39)
        {
            p += ((u32) (argv[index][i]-0x30)) << (4*(j-i));

        } 
        else if((argv[index][i] >= 0x61) && (argv[index][i] <= 0x66))
        {
            p += ((u32) (argv[index][i]-0x57)) << (4*(j-i));
        }
        else die("Input not hexdigit");
        i--;
    }
    return p;
}

u128 readK(char* arg) // u128, normaler unsigned long long
{
    int len = strlen(arg);
    if(len > 32) die("k too long");
    char* end;
    u128 p = 0;
    u32 len_second_chunk = 0;
    if(len > 16)
    {
        len_second_chunk = strlen(&arg[16]);
        p = (u128) strtoull(&arg[16],&end,16);
        if(strlen(end) != 0) die("K was read wrong1");
        arg[16] = 0;
    }
    p += ((u128) strtoull(arg,&end,16) << (4*len_second_chunk));
    if(strlen(end) != 0) die("K was read wrong2");
    return p;
}
