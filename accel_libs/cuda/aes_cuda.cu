// aes_cuda.cu
// CUDA实现的AES-128 CBC加密核心

#include "aes_cuda.h"
#include <cuda_runtime.h>
#include <stdint.h>
#include <string.h>

// AES S-box
__device__ __constant__ uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

__device__ uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

__device__ void sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

__device__ void shift_rows(uint8_t* state) {
    uint8_t tmp;
    // row 1
    tmp = state[1];
    state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    // row 2
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    // row 3
    tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;
}

__device__ void mix_columns(uint8_t* state) {
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = state[i*4]; tmp[1] = state[i*4+1]; tmp[2] = state[i*4+2]; tmp[3] = state[i*4+3];
        state[i*4]   = gmul(0x02, tmp[0]) ^ gmul(0x03, tmp[1]) ^ tmp[2] ^ tmp[3];
        state[i*4+1] = tmp[0] ^ gmul(0x02, tmp[1]) ^ gmul(0x03, tmp[2]) ^ tmp[3];
        state[i*4+2] = tmp[0] ^ tmp[1] ^ gmul(0x02, tmp[2]) ^ gmul(0x03, tmp[3]);
        state[i*4+3] = gmul(0x03, tmp[0]) ^ tmp[1] ^ tmp[2] ^ gmul(0x02, tmp[3]);
    }
}

__device__ void add_round_key(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

__device__ void key_expansion(const uint8_t* key, uint8_t* roundKeys) {
    // 只支持AES-128
    memcpy(roundKeys, key, 16);
    uint8_t temp[4];
    int i = 16, rcon = 1;
    while (i < 176) {
        for (int j = 0; j < 4; j++) temp[j] = roundKeys[i-4+j];
        if (i % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon; rcon = gmul(rcon, 2);
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }
        for (int j = 0; j < 4; j++) roundKeys[i] = roundKeys[i-16] ^ temp[j], i++;
    }
}

__device__ void aes128_encrypt_block(uint8_t* state, const uint8_t* roundKeys) {
    add_round_key(state, roundKeys);
    for (int round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, roundKeys + round*16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, roundKeys + 160);
}

__global__ void aes_cbc_encrypt_kernel(const uint8_t* in, uint8_t* out, int num_blocks, const uint8_t* key, const uint8_t* iv) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_blocks) {
        uint8_t roundKeys[176];
        key_expansion(key, roundKeys);
        uint8_t block[16];
        for (int i = 0; i < 16; i++) block[i] = in[idx*16+i];
        if (idx == 0) for (int i = 0; i < 16; i++) block[i] ^= iv[i];
        else for (int i = 0; i < 16; i++) block[i] ^= out[(idx-1)*16+i];
        aes128_encrypt_block(block, roundKeys);
        for (int i = 0; i < 16; i++) out[idx*16+i] = block[i];
    }
}

extern "C" __declspec(dllexport)
void aes_encrypt_cbc(const uint8_t* in, uint8_t* out, int length, const uint8_t* key, const uint8_t* iv) {
    int num_blocks = length / 16;
    uint8_t *d_in, *d_out, *d_key, *d_iv;
    cudaMalloc(&d_in, length);
    cudaMalloc(&d_out, length);
    cudaMalloc(&d_key, 16);
    cudaMalloc(&d_iv, 16);
    cudaMemcpy(d_in, in, length, cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, key, 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_iv, iv, 16, cudaMemcpyHostToDevice);
    int threads = 256;
    int blocks = (num_blocks + threads - 1) / threads;
    aes_cbc_encrypt_kernel<<<blocks, threads>>>(d_in, d_out, num_blocks, d_key, d_iv);
    cudaMemcpy(out, d_out, length, cudaMemcpyDeviceToHost);
    cudaFree(d_in); cudaFree(d_out); cudaFree(d_key); cudaFree(d_iv);
}

// TODO: 实现完整AES-128 CBC加密 