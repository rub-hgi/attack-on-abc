/*
  This is the C++ implementation of ABC, which is used for the masterkeyrecovery-file;
  It is not executable, but rather provides the necessary functionality for masterkeyrecovery.cpp
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

const unsigned int N_ROUNDS = 8;

using namespace std::chrono;
using namespace std::chrono_literals;

/////////////////////////////////
// Start of ABC implementation //
/////////////////////////////////
u8 SBOX[16] = {0x4, 0xc, 0x0, 0x8, 0x6, 0xe, 0x1, 0xb, 0x9, 0xd, 0x2, 0x5, 0xA, 0xF, 0x3, 0x7};

u8 DOUBLE_SBOX[256] = {
  0x44, 0x4c, 0x40, 0x48, 0x46, 0x4e, 0x41, 0x4b, 0x49, 0x4d, 0x42, 0x45, 0x4a, 0x4f, 0x43, 0x47,
  0xc4, 0xcc, 0xc0, 0xc8, 0xc6, 0xce, 0xc1, 0xcb, 0xc9, 0xcd, 0xc2, 0xc5, 0xca, 0xcf, 0xc3, 0xc7,
  0x04, 0x0c, 0x00, 0x08, 0x06, 0x0e, 0x01, 0x0b, 0x09, 0x0d, 0x02, 0x05, 0x0a, 0x0f, 0x03, 0x07,
  0x84, 0x8c, 0x80, 0x88, 0x86, 0x8e, 0x81, 0x8b, 0x89, 0x8d, 0x82, 0x85, 0x8a, 0x8f, 0x83, 0x87,
  0x64, 0x6c, 0x60, 0x68, 0x66, 0x6e, 0x61, 0x6b, 0x69, 0x6d, 0x62, 0x65, 0x6a, 0x6f, 0x63, 0x67,
  0xe4, 0xec, 0xe0, 0xe8, 0xe6, 0xee, 0xe1, 0xeb, 0xe9, 0xed, 0xe2, 0xe5, 0xea, 0xef, 0xe3, 0xe7,
  0x14, 0x1c, 0x10, 0x18, 0x16, 0x1e, 0x11, 0x1b, 0x19, 0x1d, 0x12, 0x15, 0x1a, 0x1f, 0x13, 0x17,
  0xb4, 0xbc, 0xb0, 0xb8, 0xb6, 0xbe, 0xb1, 0xbb, 0xb9, 0xbd, 0xb2, 0xb5, 0xba, 0xbf, 0xb3, 0xb7,
  0x94, 0x9c, 0x90, 0x98, 0x96, 0x9e, 0x91, 0x9b, 0x99, 0x9d, 0x92, 0x95, 0x9a, 0x9f, 0x93, 0x97,
  0xd4, 0xdc, 0xd0, 0xd8, 0xd6, 0xde, 0xd1, 0xdb, 0xd9, 0xdd, 0xd2, 0xd5, 0xda, 0xdf, 0xd3, 0xd7,
  0x24, 0x2c, 0x20, 0x28, 0x26, 0x2e, 0x21, 0x2b, 0x29, 0x2d, 0x22, 0x25, 0x2a, 0x2f, 0x23, 0x27,
  0x54, 0x5c, 0x50, 0x58, 0x56, 0x5e, 0x51, 0x5b, 0x59, 0x5d, 0x52, 0x55, 0x5a, 0x5f, 0x53, 0x57,
  0xa4, 0xac, 0xa0, 0xa8, 0xa6, 0xae, 0xa1, 0xab, 0xa9, 0xad, 0xa2, 0xa5, 0xaa, 0xaf, 0xa3, 0xa7,
  0xf4, 0xfc, 0xf0, 0xf8, 0xf6, 0xfe, 0xf1, 0xfb, 0xf9, 0xfd, 0xf2, 0xf5, 0xfa, 0xff, 0xf3, 0xf7,
  0x34, 0x3c, 0x30, 0x38, 0x36, 0x3e, 0x31, 0x3b, 0x39, 0x3d, 0x32, 0x35, 0x3a, 0x3f, 0x33, 0x37,
  0x74, 0x7c, 0x70, 0x78, 0x76, 0x7e, 0x71, 0x7b, 0x79, 0x7d, 0x72, 0x75, 0x7a, 0x7f, 0x73, 0x77};

u8 DOUBLE_SBOX_INV[256] = {
  0x22, 0x26, 0x2a, 0x2e, 0x20, 0x2b, 0x24, 0x2f, 0x23, 0x28, 0x2c, 0x27, 0x21, 0x29, 0x25, 0x2d,
  0x62, 0x66, 0x6a, 0x6e, 0x60, 0x6b, 0x64, 0x6f, 0x63, 0x68, 0x6c, 0x67, 0x61, 0x69, 0x65, 0x6d,
  0xa2, 0xa6, 0xaa, 0xae, 0xa0, 0xab, 0xa4, 0xaf, 0xa3, 0xa8, 0xac, 0xa7, 0xa1, 0xa9, 0xa5, 0xad,
  0xe2, 0xe6, 0xea, 0xee, 0xe0, 0xeb, 0xe4, 0xef, 0xe3, 0xe8, 0xec, 0xe7, 0xe1, 0xe9, 0xe5, 0xed,
  0x02, 0x06, 0x0a, 0x0e, 0x00, 0x0b, 0x04, 0x0f, 0x03, 0x08, 0x0c, 0x07, 0x01, 0x09, 0x05, 0x0d,
  0xb2, 0xb6, 0xba, 0xbe, 0xb0, 0xbb, 0xb4, 0xbf, 0xb3, 0xb8, 0xbc, 0xb7, 0xb1, 0xb9, 0xb5, 0xbd,
  0x42, 0x46, 0x4a, 0x4e, 0x40, 0x4b, 0x44, 0x4f, 0x43, 0x48, 0x4c, 0x47, 0x41, 0x49, 0x45, 0x4d,
  0xf2, 0xf6, 0xfa, 0xfe, 0xf0, 0xfb, 0xf4, 0xff, 0xf3, 0xf8, 0xfc, 0xf7, 0xf1, 0xf9, 0xf5, 0xfd,
  0x32, 0x36, 0x3a, 0x3e, 0x30, 0x3b, 0x34, 0x3f, 0x33, 0x38, 0x3c, 0x37, 0x31, 0x39, 0x35, 0x3d,
  0x82, 0x86, 0x8a, 0x8e, 0x80, 0x8b, 0x84, 0x8f, 0x83, 0x88, 0x8c, 0x87, 0x81, 0x89, 0x85, 0x8d,
  0xc2, 0xc6, 0xca, 0xce, 0xc0, 0xcb, 0xc4, 0xcf, 0xc3, 0xc8, 0xcc, 0xc7, 0xc1, 0xc9, 0xc5, 0xcd,
  0x72, 0x76, 0x7a, 0x7e, 0x70, 0x7b, 0x74, 0x7f, 0x73, 0x78, 0x7c, 0x77, 0x71, 0x79, 0x75, 0x7d,
  0x12, 0x16, 0x1a, 0x1e, 0x10, 0x1b, 0x14, 0x1f, 0x13, 0x18, 0x1c, 0x17, 0x11, 0x19, 0x15, 0x1d,
  0x92, 0x96, 0x9a, 0x9e, 0x90, 0x9b, 0x94, 0x9f, 0x93, 0x98, 0x9c, 0x97, 0x91, 0x99, 0x95, 0x9d,
  0x52, 0x56, 0x5a, 0x5e, 0x50, 0x5b, 0x54, 0x5f, 0x53, 0x58, 0x5c, 0x57, 0x51, 0x59, 0x55, 0x5d,
  0xd2, 0xd6, 0xda, 0xde, 0xd0, 0xdb, 0xd4, 0xdf, 0xd3, 0xd8, 0xdc, 0xd7, 0xd1, 0xd9, 0xd5, 0xdd};

u8 BS_BOX[256] = {
  0x9b, 0x9e, 0xa1, 0xa4, 0xa7, 0xaa, 0xad, 0xb0, 0xb3, 0xb6, 0xb9, 0xbc, 0xbf, 0xc2, 0xc5, 0xc8,
  0xcb, 0xce, 0xd1, 0xd4, 0xd7, 0xda, 0xdd, 0xe0, 0xe3, 0xe6, 0xe9, 0xec, 0xef, 0xf2, 0xf5, 0xf8,
  0xfb, 0xfe, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x10, 0x13, 0x16, 0x19, 0x1c, 0x1f, 0x22, 0x25, 0x28,
  0x2b, 0x2e, 0x31, 0x34, 0x37, 0x3a, 0x3d, 0x40, 0x43, 0x46, 0x49, 0x4c, 0x4f, 0x52, 0x55, 0x58,
  0x5b, 0x5e, 0x61, 0x64, 0x67, 0x6a, 0x6d, 0x70, 0x73, 0x76, 0x79, 0x7c, 0x7f, 0x82, 0x85, 0x88,
  0x8b, 0x8e, 0x91, 0x94, 0x97, 0x9a, 0x9d, 0xa0, 0xa3, 0xa6, 0xa9, 0xac, 0xaf, 0xb2, 0xb5, 0xb8,
  0xbb, 0xbe, 0xc1, 0xc4, 0xc7, 0xca, 0xcd, 0xd0, 0xd3, 0xd6, 0xd9, 0xdc, 0xdf, 0xe2, 0xe5, 0xe8,
  0xeb, 0xee, 0xf1, 0xf4, 0xf7, 0xfa, 0xfd, 0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15, 0x18,
  0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d, 0x30, 0x33, 0x36, 0x39, 0x3c, 0x3f, 0x42, 0x45, 0x48,
  0x4b, 0x4e, 0x51, 0x54, 0x57, 0x5a, 0x5d, 0x60, 0x63, 0x66, 0x69, 0x6c, 0x6f, 0x72, 0x75, 0x78,
  0x7b, 0x7e, 0x81, 0x84, 0x87, 0x8a, 0x8d, 0x90, 0x93, 0x96, 0x99, 0x9c, 0x9f, 0xa2, 0xa5, 0xa8,
  0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd, 0xc0, 0xc3, 0xc6, 0xc9, 0xcc, 0xcf, 0xd2, 0xd5, 0xd8,
  0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea, 0xed, 0xf0, 0xf3, 0xf6, 0xf9, 0xfc, 0xff, 0x02, 0x05, 0x08,
  0x0b, 0x0e, 0x11, 0x14, 0x17, 0x1a, 0x1d, 0x20, 0x23, 0x26, 0x29, 0x2c, 0x2f, 0x32, 0x35, 0x38,
  0x3b, 0x3e, 0x41, 0x44, 0x47, 0x4a, 0x4d, 0x50, 0x53, 0x56, 0x59, 0x5c, 0x5f, 0x62, 0x65, 0x68,
  0x6b, 0x6e, 0x71, 0x74, 0x77, 0x7a, 0x7d, 0x80, 0x83, 0x86, 0x89, 0x8c, 0x8f, 0x92, 0x95, 0x98,
};

u8 BS_BOX_INV[256] = {
  0x77, 0x22, 0xcd, 0x78, 0x23, 0xce, 0x79, 0x24, 0xcf, 0x7a, 0x25, 0xd0, 0x7b, 0x26, 0xd1, 0x7c,
  0x27, 0xd2, 0x7d, 0x28, 0xd3, 0x7e, 0x29, 0xd4, 0x7f, 0x2a, 0xd5, 0x80, 0x2b, 0xd6, 0x81, 0x2c,
  0xd7, 0x82, 0x2d, 0xd8, 0x83, 0x2e, 0xd9, 0x84, 0x2f, 0xda, 0x85, 0x30, 0xdb, 0x86, 0x31, 0xdc,
  0x87, 0x32, 0xdd, 0x88, 0x33, 0xde, 0x89, 0x34, 0xdf, 0x8a, 0x35, 0xe0, 0x8b, 0x36, 0xe1, 0x8c,
  0x37, 0xe2, 0x8d, 0x38, 0xe3, 0x8e, 0x39, 0xe4, 0x8f, 0x3a, 0xe5, 0x90, 0x3b, 0xe6, 0x91, 0x3c,
  0xe7, 0x92, 0x3d, 0xe8, 0x93, 0x3e, 0xe9, 0x94, 0x3f, 0xea, 0x95, 0x40, 0xeb, 0x96, 0x41, 0xec,
  0x97, 0x42, 0xed, 0x98, 0x43, 0xee, 0x99, 0x44, 0xef, 0x9a, 0x45, 0xf0, 0x9b, 0x46, 0xf1, 0x9c,
  0x47, 0xf2, 0x9d, 0x48, 0xf3, 0x9e, 0x49, 0xf4, 0x9f, 0x4a, 0xf5, 0xa0, 0x4b, 0xf6, 0xa1, 0x4c,
  0xf7, 0xa2, 0x4d, 0xf8, 0xa3, 0x4e, 0xf9, 0xa4, 0x4f, 0xfa, 0xa5, 0x50, 0xfb, 0xa6, 0x51, 0xfc,
  0xa7, 0x52, 0xfd, 0xa8, 0x53, 0xfe, 0xa9, 0x54, 0xff, 0xaa, 0x55, 0x00, 0xab, 0x56, 0x01, 0xac,
  0x57, 0x02, 0xad, 0x58, 0x03, 0xae, 0x59, 0x04, 0xaf, 0x5a, 0x05, 0xb0, 0x5b, 0x06, 0xb1, 0x5c,
  0x07, 0xb2, 0x5d, 0x08, 0xb3, 0x5e, 0x09, 0xb4, 0x5f, 0x0a, 0xb5, 0x60, 0x0b, 0xb6, 0x61, 0x0c,
  0xb7, 0x62, 0x0d, 0xb8, 0x63, 0x0e, 0xb9, 0x64, 0x0f, 0xba, 0x65, 0x10, 0xbb, 0x66, 0x11, 0xbc,
  0x67, 0x12, 0xbd, 0x68, 0x13, 0xbe, 0x69, 0x14, 0xbf, 0x6a, 0x15, 0xc0, 0x6b, 0x16, 0xc1, 0x6c,
  0x17, 0xc2, 0x6d, 0x18, 0xc3, 0x6e, 0x19, 0xc4, 0x6f, 0x1a, 0xc5, 0x70, 0x1b, 0xc6, 0x71, 0x1c,
  0xc7, 0x72, 0x1d, 0xc8, 0x73, 0x1e, 0xc9, 0x74, 0x1f, 0xca, 0x75, 0x20, 0xcb, 0x76, 0x21, 0xcc};


u32 S(u32 states){
  for(int i = 0; i < 4; i++){
    u8 old_byte = (states >> 8*i) & 0xFF;
    u8 new_byte = DOUBLE_SBOX[old_byte];
    states ^= ((u64) new_byte << (8*i)) ^ ((u64) old_byte << (8*i));
  }
  return states;
}

u64 S(u64 half_state){
  for(int i = 0; i < 8; i++){
    u8 old_byte = (half_state >> 8*i) & 0xFF;
    u8 new_byte = DOUBLE_SBOX[old_byte];
    half_state ^= ((u64) new_byte << (8*i)) ^ ((u64) old_byte << (8*i));
  }
  return half_state;
}

u32 S_INV(u32 states){
  for(int i = 0; i < 4; i++){
    u8 old_byte = (states >> 8*i) & 0xFF;
    u8 new_byte = DOUBLE_SBOX_INV[old_byte];
    states ^= ((u64) new_byte << (8*i)) ^ ((u64) old_byte << (8*i));
  }
  return states;
}

u64 S_INV(u64 half_state){
  for(int i = 0; i < 8; i++){
    u8 old_byte = (half_state >> 8*i) & 0xFF;
    u8 new_byte = DOUBLE_SBOX_INV[old_byte];
    half_state ^= ((u64) new_byte << (8*i)) ^ ((u64) old_byte << (8*i));
  }
  return half_state;
}

u64 r(u64 half_state){
  // order of 64-bit word in patent: byte0 || byte1 || byte2 || ... || byte7
  // r: rotate byte i by i to the right
  // where bytei = bit0 || bit1 || ... || bit7 = bit0 + 2*bit1 + ... + 128*bit7
  // i.e. least significant bit is on the left -> we must shift to the left here
  // example from patent: let w = abcdefgh. then r(w, 1) = habcdefg i.e. msb -> lsb

  for(int i = 1; i < 8; i++){
    u8 old_byte = (half_state >> (8*(7-i))) & 0xFF;
    u8 new_byte = (old_byte << i) | (old_byte >> (8-i));
    half_state ^= ((u64) (new_byte ^ old_byte)) << (8*(7-i));
  }
  return half_state;
}

// self inverse
u64 R(u64 half_state){
  // order of 64-bit word in patent: byte0 || byte1 || byte2 || ... || byte7
  /*
  |0 1|    |6 5|
  |2 3|    |2 7|
  |4 5| -> |4 1|
  |6 7|    |0 3|
  |*/
  u64 byte2_4 = half_state & 0x0000FF00FF000000;
  u64 byte1_5_3_7 = ((half_state << 32) | (half_state >> 32)) & 0x00FF00FF00FF00FF;
  u64 byte0 = (half_state >> 48) & 0x000000000000FF00;
  u64 byte6 = (half_state << 48) & 0xFF00000000000000;
  return byte2_4 ^ byte1_5_3_7 ^ byte0 ^ byte6;
}

u32 BS(u32 states){
  for(int i = 0; i < 4; i++){
    u8 old_byte = (states >> 8*i) & 0xFF;
    u8 new_byte = BS_BOX[old_byte];
    states ^= ((u64) (new_byte ^ old_byte)) << (8*i);
  }
  return states;
}

u64 BS(u64 half_state){
  for(int i = 0; i < 8; i++){
    u8 old_byte = (half_state >> 8*i) & 0xFF;
    u8 new_byte = BS_BOX[old_byte];
    half_state ^= ((u64) (new_byte ^ old_byte)) << (8*i);
  }
  return half_state;
}

u32 BS_inv(u32 states){
  for(int i = 0; i < 4; i++){
    u8 old_byte = (states >> 8*i) & 0xFF;
    u8 new_byte = BS_BOX_INV[old_byte];
    states ^= ((u64) (new_byte ^ old_byte)) << (8*i);
  }
  return states;
}

u64 BS_inv(u64 half_state){
  for(int i = 0; i < 8; i++){
    u8 old_byte = (half_state >> 8*i) & 0xFF;
    u8 new_byte = BS_BOX_INV[old_byte];
    half_state ^= ((u64) (new_byte ^ old_byte)) << (8*i);
  }
  return half_state;
}

u64 RotateXor(u64 half_state, u8 i){
  u32 left = (half_state >> 32);
  u32 right = (u32) half_state;
  u8 a = (13+i) & 0x1F;
  u8 b = (29+i) & 0x1F;
  left = left ^ ((left << a) | (left >> (32-a)));
  right = right ^ ((right << b) | (right >> (32-b)));
  return ((u64) left << 32) ^ right;
}

u128 round(u128 state, u64 round_key){
  u64 left = state >> 64; u64 right = (u64) state;
  left = R(left);
  left = left ^ r(S(right ^ round_key));
  left = BS(left);
  state = ((u128) right << 64) | left;
  return state;
}

u128 round_inv(u128 state, u64 round_key){
  u64 left = state >> 64; u64 right = (u64) state;
  right = BS_inv(right);
  right = right ^ r(S(left ^ round_key));
  right = R(right);
  state = ((u128) right << 64) | left;
  return state;
}

u128 key_schedule_round(u128 state, u8 i){
  u64 left = state >> 64; u64 right = state & 0xFFFFFFFFFFFFFFFF;
  left = left ^ R(RotateXor(S(right), i));
  left = BS(left);
  state = ((u128) right << 64) | left;
  return state;
}

void key_schedule(u64* RK, u128 key){
  u128 state = key;
  for(u32 i = 0; i < N_ROUNDS; i++){
    RK[i] = (u64) state;
    state = key_schedule_round(state, i);
  }
}

u128 encrypt(u128 plaintext, u128 key){
  u64 RK[N_ROUNDS] = {0x0};
  key_schedule(RK, key);
  u128 state = plaintext;
  for(u32 i = 0; i < N_ROUNDS; i++){
    state = round(state, RK[i]);
  }
  return state;
}

u128 decrypt(u128 ciphertext, u128 key){
  u64 RK[N_ROUNDS] = {0x0};
  key_schedule(RK, key);
  u128 state = ciphertext;
  for(u32 i = 0; i < N_ROUNDS; i++){
    state = round_inv(state, RK[N_ROUNDS-i-1]);
  }
  return state;
}

///////////////////////////////
// END of ABC implementation //
///////////////////////////////
