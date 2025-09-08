#pragma once
#include <stdint.h>
#include <cuda_runtime.h>
namespace bitcrypto { namespace gpu {
// Compara x-only(Q) (P2TR) com alvo (32 bytes). 1 = match, 0 = não.
void launch_match_p2tr(const uint8_t* d_priv32_be, const uint8_t* d_target32, uint8_t* d_hits, int count, cudaStream_t stream=0);
}}