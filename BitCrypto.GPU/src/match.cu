#include "include/bitcrypto/gpu/match_gpu.cuh"
#include "include/bitcrypto/gpu/hash_gpu.cuh"
#include "include/bitcrypto/gpu/ec_gpu.cuh"
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
#include <cuda_runtime.h>
#ifndef BITCRYPTO_CUDA_BLOCK_SIZE
#define BITCRYPTO_CUDA_BLOCK_SIZE 128
#endif
namespace bitcrypto { namespace gpu {
__device__ inline void sha256_compress_dev(uint32_t h[8], const uint8_t block[64]){
    const uint32_t K[64]={
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    #pragma unroll
    for (int i=0;i<16;i++){ w[i] = ((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|((uint32_t)block[4*i+2]<<8)|(uint32_t)block[4*i+3]; }
    #pragma unroll
    for (int i=16;i<64;i++){ uint32_t s0=(w[i-15]>>7 | w[i-15]<<25) ^ (w[i-15]>>18 | w[i-15]<<14) ^ (w[i-15]>>3); uint32_t s1=(w[i-2]>>17 | w[i-2]<<15) ^ (w[i-2]>>19 | w[i-2]<<13) ^ (w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    #pragma unroll
    for (int i=0;i<64;i++){ uint32_t S1=(e>>6|e<<26)^(e>>11|e<<21)^(e>>25|e<<7); uint32_t ch=(e&f)^((~e)&g); uint32_t t1=hh+S1+ch+K[i]+w[i]; uint32_t S0=(a>>2|a<<30)^(a>>13|a<<19)^(a>>22|a<<10); uint32_t maj=(a&b)^(a&c)^(b&c); uint32_t t2=S0+maj; hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}
__device__ inline void sha256_device(const uint8_t* data,int len,uint8_t out[32]){
    uint32_t h[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    int i=0; for(; i+64<=len; i+=64) sha256_compress_dev(h, data+i);
    uint8_t block[128]; int rem=len-i; for(int j=0;j<rem;j++) block[j]=data[i+j]; block[rem]=0x80;
    int pad=((rem+1)<=56)?(56-(rem+1)):(56+64-(rem+1)); for(int j=0;j<pad;j++) block[rem+1+j]=0x00;
    uint64_t bits=(uint64_t)len*8ull; int off=rem+1+pad; for(int j=7;j>=0;j--) block[off++]=(uint8_t)((bits>>(j*8))&0xFF);
    sha256_compress_dev(h, block); if (rem+1+pad+8 > 64) sha256_compress_dev(h, block+64);
    for(int k=0;k<8;k++){ out[4*k+0]=(uint8_t)(h[k]>>24); out[4*k+1]=(uint8_t)(h[k]>>16); out[4*k+2]=(uint8_t)(h[k]>>8); out[4*k+3]=(uint8_t)h[k]; }
}

__device__ inline uint32_t rotl32(uint32_t x,int n){ return (x<<n)|(x>>(32-n)); }
__device__ inline uint32_t f_rmd(int j,uint32_t x,uint32_t y,uint32_t z){ if(j<=15) return x^y^z; if(j<=31) return (x&y)|(~x&z); if(j<=47) return (x|~y)^z; if(j<=63) return (x&z)|(y&~z); return x^(y|~z); }
__device__ inline uint32_t K_rmd(int j){ if(j<=15) return 0x00000000u; if(j<=31) return 0x5a827999u; if(j<=47) return 0x6ed9eba1u; if(j<=63) return 0x8f1bbcdcu; return 0xa953fd4eu; }
__device__ inline uint32_t KK_rmd(int j){ if(j<=15) return 0x50a28be6u; if(j<=31) return 0x5c4dd124u; if(j<=47) return 0x6d703ef3u; if(j<=63) return 0x7a6d76e9u; return 0x00000000u; }

__device__ inline void ripemd160_compress_dev(uint32_t h[5], const uint8_t block[64]){
    const uint8_t r[80]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    const uint8_t rr[80]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    const uint8_t s[80]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
    const uint8_t ss[80]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
    uint32_t X[16]; for(int i=0;i<16;i++){ X[i]=(uint32_t)block[4*i] | ((uint32_t)block[4*i+1]<<8) | ((uint32_t)block[4*i+2]<<16) | ((uint32_t)block[4*i+3]<<24); }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4]; uint32_t A=a,B=b,C=c,D=d,E=e;
    #pragma unroll
    for(int j=0;j<80;j++){ uint32_t t=rotl32(a + f_rmd(j,b,c,d) + X[r[j]] + K_rmd(j), s[j]) + e; a=e; e=d; d=rotl32(c,10); c=b; b=t; uint32_t tt=rotl32(A + f_rmd(79-j,B,C,D) + X[rr[j]] + KK_rmd(j), ss[j]) + E; A=E; E=D; D=rotl32(C,10); C=B; B=tt; }
    uint32_t tmp=h[1]+c+D; h[1]=h[2]+d+E; h[2]=h[3]+e+A; h[3]=h[4]+a+B; h[4]=h[0]+b+C; h[0]=tmp;
}
__device__ inline void ripemd160_device(const uint8_t* data,int len,uint8_t out[20]){
    uint32_t h[5]={0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u};
    int i=0; for(; i+64<=len; i+=64) ripemd160_compress_dev(h,data+i);
    uint8_t block[128]; int rem=len-i; for(int j=0;j<rem;j++) block[j]=data[i+j]; block[rem]=0x80;
    int pad=((rem+1)<=56)?(56-(rem+1)):(56+64-(rem+1)); for(int j=0;j<pad;j++) block[rem+1+j]=0x00;
    uint64_t bits=(uint64_t)len*8ull; int off=rem+1+pad; for(int j=0;j<8;j++) block[off++]=(uint8_t)((bits>>(8*j))&0xFF);
    ripemd160_compress_dev(h, block); if (rem+1+pad+8 > 64) ripemd160_compress_dev(h, block+64);
    for(int i2=0;i2<5;i2++){ out[4*i2+0]=(uint8_t)(h[i2]&0xFF); out[4*i2+1]=(uint8_t)((h[i2]>>8)&0xFF); out[4*i2+2]=(uint8_t)((h[i2]>>16)&0xFF); out[4*i2+3]=(uint8_t)((h[i2]>>24)&0xFF); }
}
__device__ inline void hash160_device(const uint8_t* data,int len,uint8_t out20[20]){
    uint8_t t[32]; sha256_device(data,len,t); ripemd160_device(t,32,out20);
}
__global__ __launch_bounds__(BITCRYPTO_CUDA_BLOCK_SIZE) void match_p2pkh_kernel(const uint8_t* __restrict__ priv32_be,
                                   const uint8_t* __restrict__ target_h160,
                                   uint8_t* __restrict__ hits,
                                   int count, int mode)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    using namespace bitcrypto;
    const uint8_t* src = priv32_be + idx*32;
    U256 k = U256::from_be32(src); Secp256k1::scalar_mod_n(k);
    ECPointJ R = Secp256k1::scalar_mul(k, Secp256k1::G());
    ECPointA A = Secp256k1::to_affine(R);
    uint8_t buf[65]; size_t blen=0; uint8_t h[20];
    if (mode==1 || mode==2){
        encode_pubkey(A, true, buf, blen); hash160_device(buf, (int)blen, h);
        bool ok=true; for(int i=0;i<20;i++){ if(h[i]!=target_h160[i]){ ok=false; break; } } if (ok){ hits[idx]=1; return; }
    }
    if (mode==0 || mode==2){
        encode_pubkey(A, false, buf, blen); hash160_device(buf, (int)blen, h);
        bool ok=true; for(int i=0;i<20;i++){ if(h[i]!=target_h160[i]){ ok=false; break; } } if (ok){ hits[idx]=2; return; }
    }
    hits[idx]=0;
}

__device__ inline void sha256_tagged_device(const char* tag, const uint8_t* msg, int msg_len, uint8_t out32[32]){
    uint8_t th[32]; int tlen=0; while(tag[tlen]!=0) tlen++; sha256_device((const uint8_t*)tag, tlen, th);
    uint8_t buf[96]; for(int i=0;i<32;i++){ buf[i]=th[i]; buf[32+i]=th[i]; } for (int i=0;i<msg_len;i++) buf[64+i]=msg[i];
    sha256_device(buf, 64+msg_len, out32);
}
__device__ inline bitcrypto::ECPointA normalize_even_y_dev(const bitcrypto::ECPointA& A, uint8_t xonly_out[32]){
    using namespace bitcrypto; U256 y=A.y.to_u256_nm(); bool odd=(y.v[0]&1ULL)!=0ULL; ECPointA P=A; if(odd){ P.y = Fp::sub(Fp::zero(), P.y); } U256 x=P.x.to_u256_nm(); x.to_be32(xonly_out); return P;
}
__global__ __launch_bounds__(BITCRYPTO_CUDA_BLOCK_SIZE) void match_p2tr_kernel(const uint8_t* __restrict__ priv32_be,
                                  const uint8_t* __restrict__ target32,
                                  uint8_t* __restrict__ hits,
                                  int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    using namespace bitcrypto;
    const uint8_t* src = priv32_be + idx*32;
    U256 k = U256::from_be32(src); Secp256k1::scalar_mod_n(k);
    ECPointJ R = Secp256k1::scalar_mul(k, Secp256k1::G());
    ECPointA A = Secp256k1::to_affine(R);
    uint8_t xonly[32]; ECPointA Peven = normalize_even_y_dev(A, xonly);
    uint8_t t32[32]; sha256_tagged_device("TapTweak", xonly, 32, t32);
    U256 t = U256::from_be32(t32); Secp256k1::scalar_mod_n(t);
    ECPointJ tG = Secp256k1::scalar_mul(t, Secp256k1::G());
    ECPointJ Qj = Secp256k1::add(Secp256k1::to_jacobian(Peven), tG);
    ECPointA Q = Secp256k1::to_affine(Qj);
    uint8_t qx[32]; normalize_even_y_dev(Q, qx);
    bool ok=true; for (int j=0;j<32;j++){ if (qx[j]!=target32[j]) { ok=false; break; } }
    hits[idx] = ok ? 3 : 0;
}
void launch_match_p2pkh(const uint8_t* d_priv32_be, const uint8_t target_h160[20], uint8_t* d_hits, int count, int mode, cudaStream_t stream){
    int block=BITCRYPTO_CUDA_BLOCK_SIZE; int grid=(count + block - 1)/block; match_p2pkh_kernel<<<grid, block, 0, stream>>>(d_priv32_be, target_h160, d_hits, count, mode);
}
void launch_match_p2tr(const uint8_t* d_priv32_be, const uint8_t target32[32], uint8_t* d_hits, int count, cudaStream_t stream){
    int block=BITCRYPTO_CUDA_BLOCK_SIZE; int grid=(count + block - 1)/block; match_p2tr_kernel<<<grid, block, 0, stream>>>(d_priv32_be, target32, d_hits, count);
}
}}