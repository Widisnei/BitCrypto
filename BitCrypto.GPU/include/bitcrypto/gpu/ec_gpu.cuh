#pragma once
#include <bitcrypto/ec_secp256k1.h>
namespace bitcrypto { namespace gpu {
__global__ void scalar_mul_kernel(const uint8_t* __restrict__ priv32_be,
                                  uint8_t* __restrict__ pub_out,
                                  int count,
                                  int compressed);
void launch_scalar_mul(const uint8_t* d_priv32_be, uint8_t* d_pub_out, int count, bool compressed, cudaStream_t stream=0);
}}