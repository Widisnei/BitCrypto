#pragma once
#include <cstdint>
#include <cstring>
#include <array>
#include <immintrin.h>

namespace bitcrypto { namespace fe256 {

struct fe { std::array<uint64_t,4> v{}; };

static inline void fe_clear(fe& a){ a.v = {0,0,0,0}; }
static inline bool fe_is_zero(const fe& a){ return (a.v[0]|a.v[1]|a.v[2]|a.v[3])==0; }

static inline const fe& P(){ static fe p = {{ 0xFFFFFC2FULL, 0xFFFFFFFEFFFFE56DULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL }}; return p; }
static inline const fe& N(){ static fe n = {{ 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL }}; return n; }

static inline int fe_cmp(const fe& a, const fe& b){
    for (int i=3;i>=0;--i){ if (a.v[i]<b.v[i]) return -1; if (a.v[i]>b.v[i]) return 1; } return 0;
}
static inline void fe_cmov(fe& r, const fe& a, uint64_t mask){
    for (int i=0;i<4;i++){ r.v[i] = (r.v[i] & ~mask) | (a.v[i] & mask); }
}
static inline void fe_add(fe& r, const fe& a, const fe& b){
    unsigned char c=0;
    c=_addcarry_u64(c,a.v[0],b.v[0],&r.v[0]);
    c=_addcarry_u64(c,a.v[1],b.v[1],&r.v[1]);
    c=_addcarry_u64(c,a.v[2],b.v[2],&r.v[2]);
    c=_addcarry_u64(c,a.v[3],b.v[3],&r.v[3]);
    fe tmp; unsigned char brr=0;
    brr=_subborrow_u64(0,r.v[0],P().v[0],&tmp.v[0]);
    brr=_subborrow_u64(brr,r.v[1],P().v[1],&tmp.v[1]);
    brr=_subborrow_u64(brr,r.v[2],P().v[2],&tmp.v[2]);
    brr=_subborrow_u64(brr,r.v[3],P().v[3],&tmp.v[3]);
    uint64_t mask=(uint64_t)-(int)(brr==0);
    fe_cmov(r,tmp,mask);
}
static inline void fe_sub(fe& r, const fe& a, const fe& b){
    unsigned char brr=0;
    brr=_subborrow_u64(brr,a.v[0],b.v[0],&r.v[0]);
    brr=_subborrow_u64(brr,a.v[1],b.v[1],&r.v[1]);
    brr=_subborrow_u64(brr,a.v[2],b.v[2],&r.v[2]);
    brr=_subborrow_u64(brr,a.v[3],b.v[3],&r.v[3]);
    fe tmp; unsigned char c=0;
    c=_addcarry_u64(0,r.v[0],P().v[0],&tmp.v[0]);
    c=_addcarry_u64(c,r.v[1],P().v[1],&tmp.v[1]);
    c=_addcarry_u64(c,r.v[2],P().v[2],&tmp.v[2]);
    c=_addcarry_u64(c,r.v[3],P().v[3],&tmp.v[3]);
    uint64_t mask=(uint64_t)-(int)(brr!=0);
    fe_cmov(r,tmp,mask);
}

static inline void mul_512(const fe& a, const fe& b, std::array<uint64_t,8>& t){
    for(int i=0;i<8;i++) t[i]=0;
    unsigned long long hi, lo, carry, s;
    for (int i=0;i<4;i++){
        carry=0;
        for (int j=0;j<4;j++){
            lo = _umul128(a.v[i], b.v[j], &hi);
            unsigned char c1 = _addcarry_u64(0, t[i+j], lo, &s);
            unsigned char c2 = _addcarry_u64(c1, s, carry, &t[i+j]);
            unsigned char c3 = _addcarry_u64(0, t[i+j+1], hi, &t[i+j+1]);
            carry = (unsigned long long)c2 + (unsigned long long)c3;
        }
        int k=i+4; while (carry){ unsigned char c = _addcarry_u64(0, t[k], carry, &t[k]); carry=c; k++; }
    }
}
static inline void add_mul_small_977(std::array<uint64_t,4>& r, const std::array<uint64_t,4>& x){
    unsigned long long hi, lo, s; unsigned long long carry=0;
    for(int i=0;i<4;i++){
        lo=_umul128(x[i],(unsigned long long)977,&hi);
        unsigned char c1=_addcarry_u64(0,r[i],lo,&s);
        unsigned char c2=_addcarry_u64(c1,s,carry,&r[i]);
        carry=hi+(unsigned long long)c2;
    }
    while(carry){
        unsigned long long c=carry; carry=0;
        unsigned long long lo2,hi2; lo2=_umul128(c,(unsigned long long)977,&hi2);
        unsigned char d1=_addcarry_u64(0,r[0],lo2,&r[0]);
        unsigned char d2=_addcarry_u64(d1,r[1],hi2,&r[1]);
        (void)d2;
        unsigned long long s0=(c<<32), s1=(c>>32);
        unsigned char e1=_addcarry_u64(0,r[0],s0,&r[0]);
        unsigned char e2=_addcarry_u64(e1,r[1],s1,&r[1]);
        carry=e2;
    }
}
static inline void add_shift32_fold(std::array<uint64_t,4>& r, const std::array<uint64_t,4>& x){
    unsigned long long s0=(x[0]<<32);
    unsigned long long s1=(x[1]<<32)|(x[0]>>32);
    unsigned long long s2=(x[2]<<32)|(x[1]>>32);
    unsigned long long s3=(x[3]<<32)|(x[2]>>32);
    unsigned long long s4=(x[3]>>32);
    unsigned char c=0;
    c=_addcarry_u64(c,r[0],s0,&r[0]);
    c=_addcarry_u64(c,r[1],s1,&r[1]);
    c=_addcarry_u64(c,r[2],s2,&r[2]);
    c=_addcarry_u64(c,r[3],s3,&r[3]);
    unsigned long long carry=(unsigned long long)c + s4;
    while(carry){
        unsigned long long c0=carry; carry=0;
        unsigned long long lo2,hi2; lo2=_umul128(c0,(unsigned long long)977,&hi2);
        unsigned char d1=_addcarry_u64(0,r[0],lo2,&r[0]);
        unsigned char d2=_addcarry_u64(d1,r[1],hi2,&r[1]);
        (void)d2;
        unsigned long long s0b=(c0<<32), s1b=(c0>>32);
        unsigned char e1=_addcarry_u64(0,r[0],s0b,&r[0]);
        unsigned char e2=_addcarry_u64(e1,r[1],s1b,&r[1]);
        carry=e2;
    }
}
static inline void red_p(const std::array<uint64_t,8>& t, fe& r){
    std::array<uint64_t,4> lo = {t[0],t[1],t[2],t[3]};
    std::array<uint64_t,4> hi = {t[4],t[5],t[6],t[7]};
    add_mul_small_977(lo, hi);
    add_shift32_fold(lo, hi);
    r.v = lo;
    for(int k=0;k<2;k++){
        fe tmp; unsigned char brr=0;
        brr=_subborrow_u64(0,r.v[0],P().v[0],&tmp.v[0]);
        brr=_subborrow_u64(brr,r.v[1],P().v[1],&tmp.v[1]);
        brr=_subborrow_u64(brr,r.v[2],P().v[2],&tmp.v[2]);
        brr=_subborrow_u64(brr,r.v[3],P().v[3],&tmp.v[3]);
        uint64_t mask=(uint64_t)-(int)(brr==0);
        fe_cmov(r,tmp,mask);
    }
}
static inline void fe_mul(fe& r, const fe& a, const fe& b){ std::array<uint64_t,8> t; mul_512(a,b,t); red_p(t,r); }
static inline void fe_sqr(fe& r, const fe& a){ std::array<uint64_t,8> t; mul_512(a,a,t); red_p(t,r); }
static inline void fe_neg(fe& r, const fe& a){ if (fe_is_zero(a)){ fe_clear(r); return; } fe tmp; unsigned char brr=0;
    brr=_subborrow_u64(0,P().v[0],a.v[0],&tmp.v[0]);
    brr=_subborrow_u64(brr,P().v[1],a.v[1],&tmp.v[1]);
    brr=_subborrow_u64(brr,P().v[2],a.v[2],&tmp.v[2]);
    brr=_subborrow_u64(brr,P().v[3],a.v[3],&tmp.v[3]);
    r=tmp;
}
static inline fe fe_from_bytes_be(const uint8_t b[32]){
    fe a; a.v = {0,0,0,0};
    for(int i=0;i<4;i++){ uint64_t w=0; for(int j=0;j<8;j++){ w=(w<<8)|b[i*8+j]; } a.v[3-i]=w; } return a;
}
static inline void fe_to_bytes_be(uint8_t b[32], const fe& a){
    for(int i=0;i<4;i++){ uint64_t w=a.v[3-i]; for(int j=0;j<8;j++){ b[i*8+(7-j)]=(uint8_t)(w&0xFF); w>>=8; } }
}
static inline bool fe_is_odd(const fe& a){ return (a.v[0] & 1ull) != 0ull; }

// Simple fixed exponentiation for inv and sqrt (constants), using constant-time cmov
static inline void fe_pow(fe& r, const fe& a, const uint8_t* exp, size_t len){
    fe x=a; fe one; one.v={1,0,0,0}; r=one;
    for(size_t i=0;i<len;i++){
        uint8_t byte=exp[i];
        for(int b=7;b>=0;--b){
            fe_sqr(r,r);
            uint64_t mask=(uint64_t)-(int)((byte>>b)&1);
            fe t; fe_mul(t,r,x);
            r.v[0]=(r.v[0]&~mask)|(t.v[0]&mask);
            r.v[1]=(r.v[1]&~mask)|(t.v[1]&mask);
            r.v[2]=(r.v[2]&~mask)|(t.v[2]&mask);
            r.v[3]=(r.v[3]&~mask)|(t.v[3]&mask);
        }
    }
}
static inline void fe_inv(fe& r, const fe& a){
    uint8_t be[32]={
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2D,0x00,0x00,0x00,0x00
    };
    fe_pow(r,a,be,32);
}
static inline bool fe_sqrt(fe& r, const fe& a){
    uint8_t e_be[32]={
        0x3F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0x40,0x00,0x00,0x00,0x3F,0xFF,0xFF,0xF0,0x0B,0xC0,0x00,0x00
    };
    fe_pow(r,a,e_be,32); fe t; fe_sqr(t,r); return fe_cmp(t,a)==0;
}

}} // ns
