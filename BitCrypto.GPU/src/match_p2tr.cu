#include "include/bitcrypto/gpu/match_p2tr_gpu.cuh"
#include "include/bitcrypto/gpu/hash_gpu.cuh"
#include "include/bitcrypto/gpu/ec_gpu.cuh"
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
#include <cuda_runtime.h>
#include <cstring>

namespace bitcrypto { namespace gpu {

__device__ inline void tagged_sha256_device(const char* tag, const uint8_t* msg, int msg_len, uint8_t out32[32]){
    // th = sha256(tag)
    uint8_t th[32];
    sha256_device(reinterpret_cast<const uint8_t*>(tag), (int)strlen(tag), th);
    // buf = th || th || msg
    uint8_t buf[128];
    // copy th twice
    for (int i=0;i<32;i++){ buf[i]=th[i]; buf[32+i]=th[i]; }
    for (int i=0;i<msg_len;i++){ buf[64+i]=msg[i]; }
    sha256_device(buf, 64 + msg_len, out32);
}

__device__ inline void xonly_from_affine_dev(const bitcrypto::ECPointA& A, uint8_t out32[32]){
    bitcrypto::U256 x = A.x.to_u256_nm();
    x.to_be32(out32);
}

__global__ void match_p2tr_kernel(const uint8_t* __restrict__ priv32_be,
                                  const uint8_t* __restrict__ target32,
                                  uint8_t* __restrict__ hits,
                                  int count){
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    using namespace bitcrypto;

    const uint8_t* src = priv32_be + idx*32;
    U256 k = U256::from_be32(src);
    Secp256k1::scalar_mod_n(k);

    // P = k*G (affine)
    ECPointJ R = Secp256k1::scalar_mul(k, Secp256k1::G());
    ECPointA P = Secp256k1::to_affine(R);

    // xonly(P)
    uint8_t xP[32]; xonly_from_affine_dev(P, xP);

    // t = tagged_sha256("TapTweak", xP) mod n
    uint8_t th[32]; tagged_sha256_device("TapTweak", xP, 32, th);
    U256 t = U256::from_be32(th);
    Secp256k1::scalar_mod_n(t);

    // Q = P + t*G
    ECPointJ tG = Secp256k1::scalar_mul(t, Secp256k1::G());
    ECPointJ Qj = Secp256k1::add(Secp256k1::to_jacobian(P), tG);
    ECPointA Q = Secp256k1::to_affine(Qj);

    // xonly(Q)
    uint8_t xQ[32]; xonly_from_affine_dev(Q, xQ);

    // compare
    bool ok = true;
    for (int i=0;i<32;i++){ if (xQ[i] != target32[i]) { ok=false; break; } }
    hits[idx] = ok ? 1 : 0;
}

void launch_match_p2tr(const uint8_t* d_priv32_be,
                       const uint8_t* d_target32,
                       uint8_t* d_hits,
                       int count,
                       cudaStream_t stream){
    int block=128; int grid=(count + block - 1)/block;
    match_p2tr_kernel<<<grid, block, 0, stream>>>(d_priv32_be, d_target32, d_hits, count);
}

}} // ns
