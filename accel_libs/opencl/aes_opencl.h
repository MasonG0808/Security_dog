// aes_opencl.h
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
void aes_encrypt_cbc(const uint8_t* in, uint8_t* out, int length, const uint8_t* key, const uint8_t* iv);

#ifdef __cplusplus
}
#endif 