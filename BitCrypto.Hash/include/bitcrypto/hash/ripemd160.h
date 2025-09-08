#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
namespace bitcrypto { namespace hash {
struct RIPEMD160Ctx{ uint32_t h[5]; uint64_t total_len; uint8_t buf[64]; size_t idx; };
inline uint32_t rotl(uint32_t x,int n){ return (x<<n)|(x>>(32-n)); }
inline void ripemd160_init(RIPEMD160Ctx& c){ c.h[0]=0x67452301u; c.h[1]=0xefcdab89u; c.h[2]=0x98badcfeu; c.h[3]=0x10325476u; c.h[4]=0xc3d2e1f0u; c.total_len=0; c.idx=0; }
inline uint32_t f(int j,uint32_t x,uint32_t y,uint32_t z){ if(j<=15) return x^y^z; if(j<=31) return (x&y)|(~x&z); if(j<=47) return (x|~y)^z; if(j<=63) return (x&z)|(y&~z); return x^(y|~z); }
inline uint32_t K(int j){ if(j<=15) return 0x00000000u; if(j<=31) return 0x5a827999u; if(j<=47) return 0x6ed9eba1u; if(j<=63) return 0x8f1bbcdcu; return 0xa953fd4eu; }
inline uint32_t KK(int j){ if(j<=15) return 0x50a28be6u; if(j<=31) return 0x5c4dd124u; if(j<=47) return 0x6d703ef3u; if(j<=63) return 0x7a6d76e9u; return 0x00000000u; }
inline void ripemd160_compress(uint32_t h[5], const uint8_t block[64]){
    static const uint8_t r[80]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    static const uint8_t rr[80]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    static const uint8_t s[80]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
    static const uint8_t ss[80]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
    uint32_t X[16]; for(int i=0;i<16;i++){ X[i]=(uint32_t)block[4*i] | ((uint32_t)block[4*i+1]<<8) | ((uint32_t)block[4*i+2]<<16) | ((uint32_t)block[4*i+3]<<24); }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4]; uint32_t A=a,B=b,C=c,D=d,E=e;
    for(int j=0;j<80;j++){ uint32_t t=rotl(a + f(j,b,c,d) + X[r[j]] + K(j), s[j]) + e; a=e; e=d; d=rotl(c,10); c=b; b=t; uint32_t tt=rotl(A + f(79-j,B,C,D) + X[rr[j]] + KK(j), ss[j]) + E; A=E; E=D; D=rotl(C,10); C=B; B=tt; }
    uint32_t tmp = h[1] + c + D; h[1]=h[2] + d + E; h[2]=h[3] + e + A; h[3]=h[4] + a + B; h[4]=h[0] + b + C; h[0]=tmp;
}
inline void ripemd160_update(RIPEMD160Ctx& c,const uint8_t* d,size_t n){
    c.total_len+=n; size_t i=0; if(c.idx){ size_t t=64-c.idx; if(t>n) t=n; std::memcpy(c.buf+c.idx,d,t); c.idx+=t; i+=t; if(c.idx==64){ ripemd160_compress(c.h,c.buf); c.idx=0; } }
    for(;i+64<=n;i+=64) ripemd160_compress(c.h,d+i); size_t rem=n-i; if(rem){ std::memcpy(c.buf,d+i,rem); c.idx=rem; }
}
inline void ripemd160_final(RIPEMD160Ctx& c,uint8_t out[20]){
    uint8_t pad[128]; size_t padlen=0; pad[padlen++]=0x80; size_t rem=(c.idx+1)%64; size_t fill=(rem<=56)?(56-rem):(56+64-rem); std::memset(pad+padlen,0,fill); padlen+=fill;
    uint64_t bits=c.total_len*8ull; for(int i=0;i<8;i++) pad[padlen++]=(uint8_t)((bits>>(8*i))&0xFF); ripemd160_update(c,pad,padlen);
    for(int i=0;i<5;i++){ out[4*i+0]=(uint8_t)(c.h[i]&0xFF); out[4*i+1]=(uint8_t)((c.h[i]>>8)&0xFF); out[4*i+2]=(uint8_t)((c.h[i]>>16)&0xFF); out[4*i+3]=(uint8_t)((c.h[i]>>24)&0xFF); }
}
inline void ripemd160(const uint8_t* d,size_t n,uint8_t out[20]){ RIPEMD160Ctx c; ripemd160_init(c); ripemd160_update(c,d,n); ripemd160_final(c,out); }
inline void hash160(const uint8_t* d,size_t n,uint8_t out[20]);
}}