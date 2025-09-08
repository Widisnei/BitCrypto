#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <cstring>
namespace bitcrypto { namespace hash {
struct SHA256Ctx { uint32_t h[8]; uint64_t bytes; uint8_t buf[64]; size_t buf_used; };
static inline uint32_t rotr32(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
static inline void sha256_init(SHA256Ctx& c){ c.h[0]=0x6a09e667U; c.h[1]=0xbb67ae85U; c.h[2]=0x3c6ef372U; c.h[3]=0xa54ff53aU; c.h[4]=0x510e527fU; c.h[5]=0x9b05688cU; c.h[6]=0x1f83d9abU; c.h[7]=0x5be0cd19U; c.bytes=0; c.buf_used=0; }
static inline void sha256_compress(SHA256Ctx& c, const uint8_t* b){
    static const uint32_t K[64]={0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92EU,0x92722c85U,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    uint32_t w[64]; for(int i=0;i<16;i++){ w[i]=(uint32_t(b[4*i])<<24)|(uint32_t(b[4*i+1])<<16)|(uint32_t(b[4*i+2])<<8)|uint32_t(b[4*i+3]); }
    for(int i=16;i<64;i++){ uint32_t s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3); uint32_t s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=c.h[0],b_=c.h[1],c_=c.h[2],d=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],h=c.h[7];
    for(int i=0;i<64;i++){ uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25); uint32_t ch=(e&f)^((~e)&g); uint32_t t1=h+S1+ch+K[i]+w[i]; uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22); uint32_t maj=(a&b_)^(a&c_)^(b_&c_); uint32_t t2=S0+maj; h=g; g=f; f=e; e=d+t1; d=c_; c_=b_; b_=a; a=t1+t2; }
    c.h[0]+=a; c.h[1]+=b_; c.h[2]+=c_; c.h[3]+=d; c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=h;
}
static inline void sha256_update(SHA256Ctx& c, const uint8_t* data, size_t len){
    c.bytes+=len;
    if (c.buf_used){ size_t take = (len < (64 - c.buf_used)) ? len : (64 - c.buf_used); std::memcpy(c.buf + c.buf_used, data, take); c.buf_used+=take; data+=take; len-=take; if (c.buf_used==64){ sha256_compress(c, c.buf); c.buf_used=0; } }
    while(len>=64){ sha256_compress(c, data); data+=64; len-=64; }
    if (len){ std::memcpy(c.buf, data, len); c.buf_used=len; }
}
static inline void sha256_final(SHA256Ctx& c, uint8_t out32[32]){
    uint64_t bits = c.bytes*8ULL; uint8_t pad=0x80; sha256_update(c, &pad, 1); uint8_t z=0x00;
    while ((c.buf_used % 64)!=56){ sha256_update(c, &z, 1); }
    uint8_t lenbe[8]; for(int i=0;i<8;i++) lenbe[7-i]=(uint8_t)((bits>>(8*i))&0xFF); sha256_update(c, lenbe, 8);
    for(int i=0;i<8;i++){ out32[4*i+0]=(uint8_t)((c.h[i]>>24)&0xFF); out32[4*i+1]=(uint8_t)((c.h[i]>>16)&0xFF); out32[4*i+2]=(uint8_t)((c.h[i]>>8)&0xFF); out32[4*i+3]=(uint8_t)((c.h[i]>>0)&0xFF); }
}
static inline void sha256(const uint8_t* data, size_t len, uint8_t out32[32]){ SHA256Ctx c; sha256_init(c); sha256_update(c, data, len); sha256_final(c, out32); }
}}