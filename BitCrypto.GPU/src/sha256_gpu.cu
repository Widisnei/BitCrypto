#include "bitcrypto/gpu/sha256_gpu.cuh"
namespace bitcrypto { namespace gpu {
__device__ void sha256_1block(const uint8_t* b, uint8_t out32[32]){
    const uint32_t K[64]={0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92EU,0x92722c85U,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    uint32_t w[64];
    #pragma unroll
    for(int i=0;i<16;i++){ int j=4*i; w[i]=(uint32_t(b[j])<<24)|(uint32_t(b[j+1])<<16)|(uint32_t(b[j+2])<<8)|uint32_t(b[j+3]); }
    #pragma unroll
    for(int i=16;i<64;i++){ uint32_t s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3); uint32_t s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=0x6a09e667U,b_=0xbb67ae85U,c=0x3c6ef372U,d=0xa54ff53aU,e=0x510e527fU,f=0x9b05688cU,g=0x1f83d9abU,h=0x5be0cd19U;
    #pragma unroll
    for(int i=0;i<64;i++){ uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25); uint32_t ch=(e&f)^((~e)&g); uint32_t t1=h+S1+ch+K[i]+w[i]; uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22); uint32_t maj=(a&b_)^(a&c)^(b_&c); uint32_t t2=S0+maj; h=g; g=f; f=e; e=d+t1; d=c; c=b_; b_=a; a=t1+t2; }
    uint32_t H[8]={0x6a09e667U+a,0xbb67ae85U+b_,0x3c6ef372U+c,0xa54ff53aU+d,0x510e527fU+e,0x9b05688cU+f,0x1f83d9abU+g,0x5be0cd19U+h};
    #pragma unroll
    for(int i=0;i<8;i++){ out32[4*i+0]=(uint8_t)((H[i]>>24)&0xFF); out32[4*i+1]=(uint8_t)((H[i]>>16)&0xFF); out32[4*i+2]=(uint8_t)((H[i]>>8)&0xFF); out32[4*i+3]=(uint8_t)((H[i]>>0)&0xFF); }
}
__global__ void sha256_many_64B(const uint8_t* __restrict__ in, uint8_t* __restrict__ out, size_t nmsgs){
    size_t tid = blockIdx.x*blockDim.x + threadIdx.x; if (tid>=nmsgs) return;
    const uint8_t* ptr = in + tid*64; uint8_t* outp = out + tid*32; sha256_1block(ptr, outp);
}
}}