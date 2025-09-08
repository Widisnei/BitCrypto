
#pragma once
#include <cstdint>
#include <cstring>
#include <algorithm>
#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace bitcrypto { namespace ec {

struct Fe {
    uint64_t v[4]; // little-endian limbs
};

static inline void fe_set_zero(Fe& a){ a.v[0]=a.v[1]=a.v[2]=a.v[3]=0; }
static inline void fe_copy(Fe& r, const Fe& a){ r=a; }

static inline void fe_from_bytes(Fe& r, const uint8_t in[32]){
    // big-endian input
    for (int i=0;i<4;i++){
        uint64_t w=0; for (int b=0;b<8;b++) w = (w<<8) | in[i*8 + b];
        r.v[3-i]=w;
    }
}
static inline void fe_to_bytes(uint8_t out[32], const Fe& a){
    for (int i=0;i<4;i++){
        uint64_t w = a.v[3-i];
        for (int b=0;b<8;b++){ out[i*8 + (7-b)] = (uint8_t)(w & 0xFF); w >>= 8; }
    }
}

static inline bool fe_is_zero(const Fe& a){ return (a.v[0]|a.v[1]|a.v[2]|a.v[3])==0; }
static inline bool fe_eq(const Fe& a, const Fe& b){ return a.v[0]==b.v[0] && a.v[1]==b.v[1] && a.v[2]==b.v[2] && a.v[3]==b.v[3]; }

static inline int fe_cmp_raw(const Fe& a, const Fe& b){
    if (a.v[3]!=b.v[3]) return (a.v[3] > b.v[3])? 1 : -1;
    if (a.v[2]!=b.v[2]) return (a.v[2] > b.v[2])? 1 : -1;
    if (a.v[1]!=b.v[1]) return (a.v[1] > b.v[1])? 1 : -1;
    if (a.v[0]!=b.v[0]) return (a.v[0] > b.v[0])? 1 : -1;
    return 0;
}

static inline Fe fe_p(){
    Fe p; p.v[0]=0xFFFFFFFEFFFFFC2FULL; p.v[1]=0xFFFFFFFFFFFFFFFFULL; p.v[2]=0xFFFFFFFFFFFFFFFFULL; p.v[3]=0xFFFFFFFFFFFFFFFFULL; return p;
}


static inline void add64c(unsigned long long a, unsigned long long b, unsigned long long& out, unsigned char& c){
#ifdef _MSC_VER
    unsigned long long t; c = _addcarry_u64(c, a, b, &t); out = t;
#else
    unsigned __int128 s = (unsigned __int128)a + b + c; out = (unsigned long long)s; c = (unsigned char)(s>>64);
#endif
}
static inline void add512(uint64_t r[5], const uint64_t a[4], const uint64_t b[4]){
    unsigned char c=0; for (int i=0;i<4;i++) add64c(a[i], b[i], r[i], c); r[4]=c;
}
static inline void sub256_to512(uint64_t r[5], const uint64_t a[4], const uint64_t b[4]){
    unsigned char brr=0;
#ifdef _MSC_VER
    for (int i=0;i<4;i++){ unsigned long long t; brr = _subborrow_u64(brr, a[i], b[i], &t); r[i]=t; }
#else
    for (int i=0;i<4;i++){ unsigned __int128 d=(unsigned __int128)a[i]-b[i]-brr; r[i]=(uint64_t)d; brr=(unsigned char)((d>>127)&1); }
#endif
    r[4]=brr;
}
    r[4]=(uint64_t)c;
}
static inline void sub256_to512(uint64_t r[5], const uint64_t a[4], const uint64_t b[4]){
    // r = a - b as 256-bit with borrow -> if borrow, represent as a + 2^256 - b (r[4]=borrow?)
    unsigned __int128 bb=0;
    for (int i=0;i<4;i++){ unsigned __int128 d=(unsigned __int128)a[i]-b[i]-(uint64_t)bb; r[i]=(uint64_t)d; bb=(d>>127)&1; }
    r[4]=(uint64_t)bb; // 1 means underflow (we track as 2^256 added)
}

static inline void fe_reduce_p(uint64_t R[4], const uint64_t T[8]){
    // Reduce 512-bit T into 256-bit R modulo p = 2^256 - 2^32 - 977
    uint64_t lo[4]={T[0],T[1],T[2],T[3]};
    uint64_t hi[4]={T[4],T[5],T[6],T[7]};
    uint64_t R5[5]={lo[0],lo[1],lo[2],lo[3],0};

    // R += hi*977
    unsigned __int128 carry=0;
    for (int i=0;i<4;i++){
        unsigned __int128 m=(unsigned __int128)hi[i]*977u + R5[i] + (uint64_t)carry;
        R5[i]=(uint64_t)m; carry=m>>64;
    }
    R5[4] += (uint64_t)carry;

    // R += hi<<32 (low part)
    carry=0;
    for (int i=0;i<4;i++){
        unsigned __int128 s = (unsigned __int128)R5[i] + ((unsigned __int128)hi[i] << 32) + (uint64_t)carry;
        R5[i]=(uint64_t)s; carry=s>>64;
    }
    R5[4] += (uint64_t)carry;

    // R += (hi>>32) shifted to next limb
    carry=0;
    for (int i=0;i<4;i++){
        unsigned __int128 s = (unsigned __int128)R5[i+1] + (hi[i] >> 32) + (uint64_t)carry;
        R5[i+1]=(uint64_t)s; carry=s>>64;
    }
    // fold overflow repeatedly
    while (R5[4]){
        uint64_t k = R5[4]; R5[4]=0;
        // add k*977
        unsigned __int128 c=0;
        for (int i=0;i<4;i++){
            unsigned __int128 m=(unsigned __int128)R5[i] + (unsigned __int128)k*977u + (uint64_t)c;
            R5[i]=(uint64_t)m; c=m>>64;
        }
        R5[4] += (uint64_t)c;
        // add k<<32
        c=0;
        for (int i=0;i<4;i++){
            unsigned __int128 s=(unsigned __int128)R5[i] + ((unsigned __int128)k<<32) + (uint64_t)c;
            R5[i]=(uint64_t)s; c=s>>64;
        }
        R5[4] += (uint64_t)c;
        // add (k>>32) to next limb
        c=0;
        for (int i=0;i<4;i++){
            unsigned __int128 s=(unsigned __int128)R5[i+1] + (k>>32) + (uint64_t)c;
            R5[i+1]=(uint64_t)s; c=s>>64;
        }
    }
    // final conditional reductions
    Fe p = fe_p();
    Fe r; r.v[0]=R5[0]; r.v[1]=R5[1]; r.v[2]=R5[2]; r.v[3]=R5[3];
    // while r >= p: r -= p
    for (int k=0;k<2;k++){
        int ge = fe_cmp_raw(r,p)>=0;
        if (ge){
            unsigned __int128 bb=0; Fe t;
            for (int i=0;i<4;i++){ unsigned __int128 d=(unsigned __int128)r.v[i] - p.v[i] - (uint64_t)bb; t.v[i]=(uint64_t)d; bb=(d>>127)&1; }
            r=t;
        }
    }
    R[0]=r.v[0]; R[1]=r.v[1]; R[2]=r.v[2]; R[3]=r.v[3];
}

static inline void fe_add(Fe& r, const Fe& a, const Fe& b){
    uint64_t T[8]={0};
    unsigned __int128 c=0;
    uint64_t s[4];
    for(int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)a.v[i]+b.v[i]; s[i]=(uint64_t)t; c = (t>>64); if (i<3) T[4+i]=0; }
    // Build 512-bit as lo=s, hi=carry (carry in limb 0) to reduce correctly
    T[0]=s[0]; T[1]=s[1]; T[2]=s[2]; T[3]=s[3];
    T[4]=(uint64_t)c; T[5]=T[6]=T[7]=0;
    fe_reduce_p(r.v, T);
}


static inline void fe_sub(Fe& r, const Fe& a, const Fe& b){
#ifdef _MSC_VER
    unsigned char brr=0; unsigned long long t0,t1,t2,t3;
    brr = _subborrow_u64(brr, a.v[0], b.v[0], &t0);
    brr = _subborrow_u64(brr, a.v[1], b.v[1], &t1);
    brr = _subborrow_u64(brr, a.v[2], b.v[2], &t2);
    brr = _subborrow_u64(brr, a.v[3], b.v[3], &t3);
    if (brr){
        // add p
        unsigned char c=0;
        Fe p = fe_p();
        c = _addcarry_u64(c, t0, p.v[0], &t0);
        c = _addcarry_u64(c, t1, p.v[1], &t1);
        c = _addcarry_u64(c, t2, p.v[2], &t2);
        c = _addcarry_u64(c, t3, p.v[3], &t3);
    }
    r.v[0]=t0; r.v[1]=t1; r.v[2]=t2; r.v[3]=t3;
#else
    unsigned __int128 bb=0;
    uint64_t lo[4];
    for(int i=0;i<4;i++){ unsigned __int128 d=(unsigned __int128)a.v[i]-b.v[i]-(uint64_t)bb; lo[i]=(uint64_t)d; bb=(d>>127)&1; }
    if (bb){
        unsigned __int128 c=0; Fe p = fe_p();
        for (int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)lo[i]+p.v[i]+(uint64_t)c; lo[i]=(uint64_t)t; c=t>>64; }
    }
    r.v[0]=lo[0]; r.v[1]=lo[1]; r.v[2]=lo[2]; r.v[3]=lo[3];
#endif
}
    if (bb){
        // add p
        unsigned __int128 c=0; Fe p = fe_p();
        for (int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)lo[i]+p.v[i]+(uint64_t)c; lo[i]=(uint64_t)t; c=t>>64; }
    }
    r.v[0]=lo[0]; r.v[1]=lo[1]; r.v[2]=lo[2]; r.v[3]=lo[3];
}

static inline void fe_mul(Fe& r, const Fe& a, const Fe& b){
    uint64_t T[8]={0};
    for (int i=0;i<4;i++){
        unsigned __int128 carry=0;
        for (int j=0;j<4;j++){
            unsigned __int128 m=(unsigned __int128)a.v[i]*b.v[j] + T[i+j] + (uint64_t)carry;
            T[i+j]=(uint64_t)m; carry = m>>64;
        }
        T[i+4] += (uint64_t)carry;
    }
    fe_reduce_p(r.v, T);
}
static inline void fe_sqr(Fe& r, const Fe& a){ fe_mul(r,a,a); }

static inline void fe_pow(Fe& r, const Fe& a, const uint64_t e[4]){
    Fe result; fe_set_zero(result); result.v[0]=1;
    Fe base=a;
    for (int i=3;i>=0;i--){
        for (int b=63;b>=0;b--){
            // result = result^2
            fe_sqr(result, result);
            if ((e[i]>>b)&1ULL){
                fe_mul(result, result, base);
            }
        }
    }
    r=result;
}
static inline void fe_const_p_minus_2(uint64_t e[4]){
    Fe p=fe_p();
    // e = p - 2
    unsigned __int128 bb=0;
    uint64_t two[4]={2,0,0,0};
    for (int i=0;i<4;i++){
        unsigned __int128 d=(unsigned __int128)p.v[i]-two[i]-(uint64_t)bb; e[i]=(uint64_t)d; bb=(d>>127)&1;
    }
}
static inline void fe_const_p_plus1_div4(uint64_t e[4]){
    Fe p=fe_p();
    // tmp = p + 1
    unsigned __int128 c=1;
    uint64_t tmp[4];
    for (int i=0;i<4;i++){ unsigned __int128 s=(unsigned __int128)p.v[i]+(uint64_t)c; tmp[i]=(uint64_t)s; c=s>>64; }
    // e = tmp >> 2
    e[0] = (tmp[0]>>2) | (tmp[1]<<(62));
    e[1] = (tmp[1]>>2) | (tmp[2]<<(62));
    e[2] = (tmp[2]>>2) | (tmp[3]<<(62));
    e[3] = (tmp[3]>>2);
}
static inline void fe_inv(Fe& r, const Fe& a){
    uint64_t e[4]; fe_const_p_minus_2(e);
    fe_pow(r,a,e);
}
static inline bool fe_sqrt(Fe& r, const Fe& a){
    // For p % 4 == 3, sqrt = a^{(p+1)/4}
    uint64_t e[4]; fe_const_p_plus1_div4(e);
    fe_pow(r,a,e);
    // Check r^2 == a
    Fe t; fe_sqr(t,r);
    return fe_eq(t,a);
}
static inline bool fe_is_odd(const Fe& a){ return (a.v[0] & 1ULL) != 0; }

}} // ns
