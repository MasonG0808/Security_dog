// aes_opencl.c
// OpenCL实现的AES-128 CBC加密核心（示例）

#include "aes_opencl.h"
#include <CL/cl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// OpenCL AES-128单块加密内核（简化版，实际可参考成熟实现）
const char* kernel_src =
"__constant uchar sbox[256] = {\n"
"0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,"
"0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,"
"0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,"
"0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,"
"0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,"
"0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,"
"0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,"
"0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,"
"0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,"
"0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,"
"0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,"
"0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,"
"0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,"
"0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,"
"0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,"
"0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};\n"
"void sub_bytes(__global uchar* state) { for(int i=0;i<16;i++) state[i]=sbox[state[i]]; }\n"
"void shift_rows(__global uchar* state) { uchar t; t=state[1];state[1]=state[5];state[5]=state[9];state[9]=state[13];state[13]=t; t=state[2];state[2]=state[10];state[10]=t; t=state[6];state[6]=state[14];state[14]=t; t=state[3];state[3]=state[15];state[15]=state[11];state[11]=state[7];state[7]=t; }\n"
"uchar gmul(uchar a, uchar b) { uchar p=0; for(int i=0;i<8;i++){ if(b&1)p^=a; uchar hi=a&0x80; a<<=1; if(hi)a^=0x1b; b>>=1;} return p;}\n"
"void mix_columns(__global uchar* state) { uchar t[4]; for(int i=0;i<4;i++){ t[0]=state[i*4];t[1]=state[i*4+1];t[2]=state[i*4+2];t[3]=state[i*4+3]; state[i*4]=gmul(0x02,t[0])^gmul(0x03,t[1])^t[2]^t[3]; state[i*4+1]=t[0]^gmul(0x02,t[1])^gmul(0x03,t[2])^t[3]; state[i*4+2]=t[0]^t[1]^gmul(0x02,t[2])^gmul(0x03,t[3]); state[i*4+3]=gmul(0x03,t[0])^t[1]^t[2]^gmul(0x02,t[3]);}}\n"
"void add_round_key(__global uchar* state, __global uchar* roundKey) { for(int i=0;i<16;i++) state[i]^=roundKey[i]; }\n"
"void key_expansion(__global uchar* key, __global uchar* roundKeys) { for(int i=0;i<16;i++) roundKeys[i]=key[i]; uchar temp[4]; int i=16,rcon=1; while(i<176){ for(int j=0;j<4;j++) temp[j]=roundKeys[i-4+j]; if(i%16==0){ uchar t=temp[0]; temp[0]=sbox[temp[1]]^rcon; rcon=gmul(rcon,2); temp[1]=sbox[temp[2]]; temp[2]=sbox[temp[3]]; temp[3]=sbox[t]; } for(int j=0;j<4;j++) roundKeys[i]=roundKeys[i-16]^temp[j],i++;}}\n"
"void aes128_encrypt_block(__global uchar* state, __global uchar* roundKeys) { add_round_key(state,roundKeys); for(int round=1;round<10;round++){ sub_bytes(state); shift_rows(state); mix_columns(state); add_round_key(state,roundKeys+round*16);} sub_bytes(state); shift_rows(state); add_round_key(state,roundKeys+160);}\n"
"__kernel void aes_cbc_encrypt(__global const uchar* in, __global uchar* out, int num_blocks, __global uchar* key, __global uchar* iv) { int idx=get_global_id(0); if(idx<num_blocks){ __global uchar* roundKeys=out+num_blocks*16; key_expansion(key,roundKeys); uchar block[16]; for(int i=0;i<16;i++) block[i]=in[idx*16+i]; if(idx==0) for(int i=0;i<16;i++) block[i]^=iv[i]; else for(int i=0;i<16;i++) block[i]^=out[(idx-1)*16+i]; aes128_encrypt_block(block,roundKeys); for(int i=0;i<16;i++) out[idx*16+i]=block[i]; } }";

void aes_encrypt_cbc(const uint8_t* in, uint8_t* out, int length, const uint8_t* key, const uint8_t* iv) {
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_mem buf_in, buf_out, buf_key, buf_iv;
    size_t global_size;
    int num_blocks = length / 16;
    cl_int err;

    err = clGetPlatformIDs(1, &platform, NULL);
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    queue = clCreateCommandQueue(context, device, 0, &err);
    program = clCreateProgramWithSource(context, 1, &kernel_src, NULL, &err);
    err = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
    kernel = clCreateKernel(program, "aes_cbc_encrypt", &err);

    buf_in = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, length, (void*)in, &err);
    buf_out = clCreateBuffer(context, CL_MEM_READ_WRITE, length + 176, NULL, &err); // 多分配176字节用于轮密钥
    buf_key = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 16, (void*)key, &err);
    buf_iv = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 16, (void*)iv, &err);

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf_in);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &buf_out);
    clSetKernelArg(kernel, 2, sizeof(int), &num_blocks);
    clSetKernelArg(kernel, 3, sizeof(cl_mem), &buf_key);
    clSetKernelArg(kernel, 4, sizeof(cl_mem), &buf_iv);

    global_size = num_blocks;
    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, NULL, 0, NULL, NULL);
    clFinish(queue);
    clEnqueueReadBuffer(queue, buf_out, CL_TRUE, 0, length, out, 0, NULL, NULL);

    clReleaseMemObject(buf_in);
    clReleaseMemObject(buf_out);
    clReleaseMemObject(buf_key);
    clReleaseMemObject(buf_iv);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
}

// TODO: 实现完整AES-128 CBC加密，支持OpenCL并行 