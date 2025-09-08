#pragma once
#include <cstdint>
#include <cstddef>
#if !defined(__CUDA_ARCH__) && defined(_MSC_VER)
  #include <intrin.h>
#endif
#if defined(__CUDACC__)
  #define BITCRYPTO_HD __host__ __device__
#else
  #define BITCRYPTO_HD
#endif
#if defined(__CUDA_ARCH__)
  #define BITCRYPTO_DEVICE 1
#else
  #define BITCRYPTO_DEVICE 0
#endif
BITCRYPTO_HD inline void mul64x64_128(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo){
#if BITCRYPTO_DEVICE
    lo = a*b; hi = __umul64hi(a,b);
#else
  #if defined(_MSC_VER) && defined(_M_X64)
    unsigned __int64 hi_local; unsigned __int64 lo_local = _umul128(a,b,&hi_local); hi=hi_local; lo=lo_local;
  #else
    __uint128_t r = ( (__uint128_t)a * b ); lo=(uint64_t)r; hi=(uint64_t)(r>>64);
  #endif
#endif
}
BITCRYPTO_HD inline uint64_t addc64(uint64_t a,uint64_t b,uint64_t& c){ uint64_t t=a+c; uint64_t r=t+b; c=(t<a)||(r<t); return r; }
BITCRYPTO_HD inline uint64_t subb64(uint64_t a,uint64_t b,uint64_t& br){ uint64_t t=a-b-br; uint64_t bb=(a<b)||(br && a==b); br=bb; return t; }
BITCRYPTO_HD inline void cswap64(uint64_t& a,uint64_t& b,uint64_t m){ uint64_t x=(a^b)&m; a^=x; b^=x; }
// Apaga memória de forma segura
BITCRYPTO_HD inline void secure_memzero(void* v, size_t n){
#if BITCRYPTO_DEVICE
    uint8_t* p = reinterpret_cast<uint8_t*>(v);
    for (size_t i=0;i<n;i++) p[i]=0;
#else
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(v);
    while (n--) *p++ = 0;
#endif
}
