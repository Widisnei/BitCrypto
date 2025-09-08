#include "include/bitcrypto/gpu/taproot_gpu.cuh"
#include "include/bitcrypto/gpu/hash_gpu.cuh"
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
#include "../../BitCrypto.Core/include/bitcrypto/base.h"
#include <cuda_runtime.h>
#include <string.h>

namespace bitcrypto { namespace gpu {

__device__ inline void sha256_tagged_device(const char* tag, const uint8_t* data, int len, uint8_t out[32]){
    uint8_t th[32]; sha256_device((const uint8_t*)tag, (int)strlen(tag), th);
    uint8_t buf[32+32+64];
    for (int i=0;i<32;i++){ buf[i]=th[i]; buf[32+i]=th[i]; }
    for (int i=0;i<len;i++) buf[64+i]=data[i];
    sha256_device(buf, 64+len, out);
}

__device__ inline void xonly_even_dev(const bitcrypto::ECPointA& Pin, uint8_t x32[32], bool& neg){
    using namespace bitcrypto;
    U256 y = Pin.y.to_u256_nm();
    bool odd = (y.v[0] & 1ULL) != 0ULL;
    ECPointA P = Pin;
    if (odd){ P.y = Fp::sub(Fp::zero(), P.y); neg=true; } else { neg=false; }
    U256 x = P.x.to_u256_nm(); x.to_be32(x32);
}

__global__ void match_p2tr_kernel(const uint8_t* __restrict__ priv32_be,
                                  const uint8_t* __restrict__ target32,
                                  uint8_t* __restrict__ hits,
                                  int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    using namespace bitcrypto;

    U256 k = U256::from_be32(priv32_be + idx*32);
    Secp256k1::scalar_mod_n(k);
    auto P = Secp256k1::derive_pubkey(k);

    uint8_t xonly[32]; bool neg=false;
    xonly_even_dev(P, xonly, neg);

    uint8_t t32[32]; sha256_tagged_device("TapTweak", xonly, 32, t32);
    U256 t = U256::from_be32(t32);
    Secp256k1::scalar_mod_n(t);

    ECPointJ tG = Secp256k1::scalar_mul(t, Secp256k1::G());
    ECPointJ Qj = Secp256k1::add(Secp256k1::to_jacobian(P), tG);
    ECPointA Q = Secp256k1::to_affine(Qj);

    uint8_t qx[32]; bool _n=false; xonly_even_dev(Q, qx, _n);

    bool ok=true; for(int i=0;i<32;i++){ if(qx[i]!=target32[i]){ ok=false; break; } }
    hits[idx] = ok ? 1 : 0;
}

void launch_match_p2tr(const uint8_t* d_priv32_be, const uint8_t* d_target32, uint8_t* d_hits, int count, cudaStream_t stream){
    int block=128; int grid=(count + block - 1)/block;
    match_p2tr_kernel<<<grid, block, 0, stream>>>(d_priv32_be, d_target32, d_hits, count);
}

}}