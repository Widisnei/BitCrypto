#pragma once
#include <stdint.h>
namespace bitcrypto { namespace gpu {
__device__ inline uint32_t rotr32(uint32_t x,int n){ return (x>>n)|(x<<(32-n)); }
__device__ inline void sha256_device(const uint8_t* data,int len,uint8_t out[32]);
__device__ inline void ripemd160_device(const uint8_t* data,int len,uint8_t out[20]);
__device__ inline void hash160_device(const uint8_t* data,int len,uint8_t out20[20]);
}}