#include "include/bitcrypto/gpu/ec_gpu.cuh"
#include <cuda_runtime.h>
#ifndef BITCRYPTO_CUDA_BLOCK_SIZE
#define BITCRYPTO_CUDA_BLOCK_SIZE 128
#endif
namespace bitcrypto { namespace gpu {
__global__ __launch_bounds__(BITCRYPTO_CUDA_BLOCK_SIZE) void scalar_mul_kernel(const uint8_t* __restrict__ priv32_be,
                                  uint8_t* __restrict__ pub_out,
                                  int count,
                                  int compressed)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    using namespace bitcrypto;
    U256 k = U256::from_be32(priv32_be + idx*32);
    Secp256k1::scalar_mod_n(k);
    auto G = Secp256k1::G();
    ECPointJ R = Secp256k1::scalar_mul(k, G);
    ECPointA A = Secp256k1::to_affine(R);
    size_t out_len=0; encode_pubkey(A, compressed!=0, pub_out + idx*(compressed?33:65), out_len);
}
void launch_scalar_mul(const uint8_t* d_priv32_be, uint8_t* d_pub_out, int count, bool compressed, cudaStream_t stream){
    int block=BITCRYPTO_CUDA_BLOCK_SIZE; int grid=(count + block - 1)/block;
    scalar_mul_kernel<<<grid, block, 0, stream>>>(d_priv32_be, d_pub_out, count, compressed?1:0);
}
}}