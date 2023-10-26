/*
    This file aims to recover the masterkey, given the k_B2 and k_B4. 
    It uses the "optimal" strategy found by the greedy algorithm; The running time is not really realistic
    on basic computers, but rather on Clusters or "Supercomputers" (2^49 candidates to check at max).

    Thus it should rather show the approach to determine less than all 128 bits of the masterkey, but rather 
    a few dozen, which finishes in a few minutes.
    The results of the keyrecovery (all candidates found by then) are written into:

    #---------------#
    |   ./results   |
    #---------------#

    This algorithm works recursively, for every candidate that remains after the 1-bit check of the rks,
    we try the next bits and check again (and so on) ...

    As it would not make sense to save ALL candidates that satisfied these checks, we looked at the following:

    If each bit, which was guessed by now, was set correctly (realising this with bitwise and), then we consider it as a 
    correct key-candidate (not many remain). This of course requires the knowledge of the masterkey, but 
    can be realised in theory, as again this program is for analysis purposes rather than for the actual full recovery.

*/


#include <iostream>
#include <omp.h>
#include <cstdint>
#include <chrono>
#include <unistd.h>
#include <array>
#include <vector>
#include <algorithm>
#include <sys/random.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __uint128_t u128;

void key_schedule(u64* RK, u128 key);
u128 key_schedule_round(u128 state, u8 i);

void print128(u128 mk)
{
    printf("%016llx%016llx ",(u64) (mk>>64),(u64) (mk & 0xffffffffffffffff));
}

void space(u8 num)
{
    printf("[%d]",num);
    while(num > 0)
    {
        printf("\t");
        num--;
    }
}

u8 adjust(u8 num)
{
    return (7-(num % 8)) + 8*(num/8);
}

static void die(const char* msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
static const unsigned int LEN_POSITIONS = 18;

const unsigned int N_ROUNDS = 8;
const unsigned int N_BREAK = LEN_POSITIONS-1; 
static u128 mk,rks,mask_guess;

static FILE* file;
static char tmp[36];

//---------------TODO---------------//
int POSITIONS[LEN_POSITIONS][128] = {
    {0x10,0x40,0x41,0x43,-1},
    {0x11,0x44,0x45,0x46,0x47,-1},
    {0x12,-1},
    {0x13,-1},
    {0x14,-1},
    {0x15,0x58,0x59,0x5a,0x5b,-1},
    {0x16,-1},
    {0x17,-1},
    {0x20,-1},
    {0x21,-1},
    {0x22,-1},
    {0x23,-1},
    {0x24,-1},
    {0x25,0x78,0x79,0x7a,0x7b,-1},
    {0x26,-1},
    {0x27,-1},
    {-1}
};

//---------------TODO---------------//
u8 REIHENFOLGE[LEN_POSITIONS-1] = {0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10,
                0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x19,0x18};




u128 phi(u128 mk) // => k -> (k_{b2,r}, k_{b4,r}) for r < 8
{
    u128 result = 0;
    u64* RK = (u64*) malloc(8*sizeof(u64));
    key_schedule(RK,mk);
    for(u8 i = 0;i < N_ROUNDS;i++)
    {
        result <<= 16;
        result |= (((RK[i] >> 40) & 0xff) << 8) + ((RK[i] >> 24) & 0xff) ;
    }
    return result;
}

u64* attack(int* positions,u128 known_from_the_start,u8 recursion_depth, u64 ctrs[2]) // ctrs[0] == ctr, ctrs[1] == ctr_hits
{
    if(recursion_depth == N_BREAK) return ctrs;
    
    space(recursion_depth);printf("START: %d, ctrs: (%llu, %llu) \n",recursion_depth,ctrs[0],ctrs[1]);
    
    // Finde anzahl der zu ratenen bits raus
    u8 len_positions = 0;
    while(positions[len_positions++] != -1);
    len_positions--;

    // Wenn am ende angekommen
    if(positions[0] == -1 || len_positions <= 0) return ctrs; 

    u16 len_cands = 1;
    u128* cands = (u128*) malloc(len_cands*sizeof(u128));
    if(cands == NULL) die("malloc");
    cands[0] = 0;
    
    u128 guess,rks_guess;
    u8 digit = REIHENFOLGE[recursion_depth]; // Bitnr vom RK 
    u64 j;

    for(u64 i = 0;i < (u64) (1<<len_positions);i++)
    {
        j = i;
        u8 l = 0;
        guess = known_from_the_start;
        mask_guess |= known_from_the_start;

        while(j > 0) // Put for-loop-counter into guessed positions
        {
            mask_guess |= ((u128) 1) << (127-adjust(positions[l])); 
            guess |= ( ((u128) (j & 1)) << (127-adjust(positions[l])));
            l++;
            j>>=1;
        }

        

        rks_guess = phi(guess);

        space(recursion_depth);printf("(");print128(guess);printf(")\t");
        printf("%hhu %hhu %s\n",(u8) ((rks_guess>>(127-adjust(digit))) & 1),(u8) ((rks>>(127-adjust(digit))) & 1),((mk & mask_guess) == guess) ? "True" : "False"); // 
        if( ( (rks_guess >> (127-(digit))) & 1) == ( (rks >> (127-(digit)))  & 1) ) // Wenn das bit von RK übereinstimmt 
        {
            len_cands++;
            cands = (u128*) realloc(cands,len_cands*sizeof(u128));
            if(cands == NULL) die("realloc");
            cands[len_cands-2] = guess;

            ctrs[0]++;
            
                
            if(recursion_depth == N_BREAK-1)
            {
                // if(recursion_depth == N_BREAK-1)
                if((mk & mask_guess) == guess)
                {
                    ctrs[1]++;
                    // Write into file
                    char tmp[36];
                    if(snprintf(tmp,36,"%016llx%016llx\n",(u64) (guess>>64),(u64) (guess & 0xffffffffffffffff)) < 0) die("snprintf");
                    fputs(tmp,file);
                }

            }

            u64* result = attack(POSITIONS[recursion_depth+1],guess,recursion_depth+1,ctrs);

            ctrs[0] = result[0];
            ctrs[1] = result[1];

        }

    }
    
    space(recursion_depth);printf("END: %d, ctrs: (%llu, %llu) \n",recursion_depth,ctrs[0],ctrs[1]);
    return ctrs;
}


int main()
{
    getentropy(&mk,16);
    rks = phi(mk);
    print128(mk);
    file = fopen("results","w");

    if(snprintf(tmp,36,"%llx%llx\n\n",(u64) (mk>>64),(u64) (mk & 0xffffffffffffffff)) < 0) die("snprintf");
    fputs(tmp,file);
    


    print128(rks);
    printf("\n");

    u128 known_mk = (((rks >> (128-8)) & 0xff) << (64-8-0x10)) + (((rks >> (128-16)) & 0xff) << (64-8-0x20));
    print128(known_mk);
    u64* ctrs = (u64*) malloc(2*sizeof(u64));
    ctrs[0] = 0;
    ctrs[1] = 0;

    printf("\n\n\n");
    attack(POSITIONS[0],known_mk,0,ctrs);

    if(fclose(file)) die("fclose");


    return EXIT_SUCCESS;
}
