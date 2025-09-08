#pragma once
#include <cuda_runtime.h>
#include <stdint.h>
namespace bitcrypto { namespace gpu {
__device__ __forceinline__ uint32_t rotr32(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
__device__ void sha256_1block(const uint8_t* block64, uint8_t out32[32]);
__global__ void sha256_many_64B(const uint8_t* __restrict__ in, uint8_t* __restrict__ out, size_t nmsgs);
}}