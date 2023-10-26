#ifndef APPLECIPHER_H
#define APPLECIPHER_H


typedef __uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __uint128_t u128;

typedef struct {
    u8 data[16];
} state128;

typedef struct {
    u8 data[8];
} state64;



void exit_err(char* msg);
int S(int i,bool inv);
state64 xor64( state64 a,  state64 b);
state128 xor128( state128 a,  state128 b);
#define xor(x, y) _Generic((x),  state64: xor64,  state128: xor128)(x, y)
void print64(state64 num);
void print128(state128 num);
#define print(num) _Generic((num), state128: print128, state64: print64)(num)

state64 sLayer( state64 input,bool inv);
state64 r( state64 input,bool inv);
state64 bigR( state64 input);
state64 bs( state64 input,bool inv);
state64 rotateXOR( state64 input,int round);
state128 runde( state128 input, state64 key,bool inv);
state128 ksround( state128 input,int round);
state64* keyschedule( state128 mk,int rounds);
state128 apl_encrypt( state128 p,  state128 mk,int rounds);
state128 read128(char* argv[],int index);

#endif