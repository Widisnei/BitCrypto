#pragma once
#include <stdint.h>
#include <cuda_runtime.h>
#ifndef BITCRYPTO_CUDA_BLOCK_SIZE
#define BITCRYPTO_CUDA_BLOCK_SIZE 128
#endif
namespace bitcrypto { namespace gpu {
// compressed_mode: 0=uncompressed, 1=compressed, 2=both
void launch_match_p2pkh(const uint8_t* d_priv32_be, const uint8_t target_h160[20], uint8_t* d_hits, int count, int compressed_mode, cudaStream_t stream=0);
// P2TR (Taproot) match
void launch_match_p2tr(const uint8_t* d_priv32_be, const uint8_t target32[32], uint8_t* d_hits, int count, cudaStream_t stream=0);
}}