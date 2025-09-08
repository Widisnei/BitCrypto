#pragma once
#include <cstdint>
#include <cstring>
#include <array>
#include "../math/fe256.h"

namespace bitcrypto { namespace ec {

using bitcrypto::fe256::fe;
using namespace bitcrypto::fe256;

struct PointA { fe x; fe y; bool inf=false; };
struct PointJ { fe X; fe Y; fe Z; bool inf=false; };

static inline fe FE_SEVEN(){ fe t; t.v={7,0,0,0}; return t; }

static inline PointA G(){
    const uint8_t x_be[32]={0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98};
    const uint8_t y_be[32]={0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8};
    PointA P; P.x=fe_from_bytes_be(x_be); P.y=fe_from_bytes_be(y_be); P.inf=false; return P;
}

static inline void pj_from_affine(const PointA& A, PointJ& R){ R.X=A.x; R.Y=A.y; R.Z.v={1,0,0,0}; R.inf=A.inf; }
static inline void pa_from_jacobian(const PointJ& J, PointA& A){
    if(J.inf){ A.inf=true; return; }
    fe z2,z3,zinv; fe_inv(zinv,J.Z); fe_sqr(z2,zinv); fe_mul(z3,z2,zinv);
    fe_mul(A.x,J.X,z2); fe_mul(A.y,J.Y,z3); A.inf=false;
}
static inline PointJ INF(){ PointJ R; R.inf=true; fe_clear(R.X); fe_clear(R.Y); fe_clear(R.Z); return R; }

static inline void pj_double(const PointJ& P, PointJ& R){
    if (P.inf){ R=P; return; }
    fe XX,YY,YYYY,S,M,T;
    fe_sqr(XX,P.X);
    fe_sqr(YY,P.Y);
    fe_sqr(YYYY,YY);
    fe_mul(S,P.X,YY); fe_add(S,S,S);
    fe_add(M,XX,XX); fe_add(M,M,XX);
    fe_sqr(R.X,M);
    fe_add(T,S,S);
    fe_sub(R.X,R.X,T);
    fe_sub(T,S,R.X);
    fe_mul(T,M,T);
    fe_add(YYYY,YYYY,YYYY); fe_add(YYYY,YYYY,YYYY); fe_add(YYYY,YYYY,YYYY);
    fe_sub(R.Y,T,YYYY);
    fe_mul(R.Z,P.Y,P.Z); fe_add(R.Z,R.Z,R.Z);
    R.inf=false;
}

static inline void pj_add(const PointJ& P, const PointJ& Q, PointJ& R){
    if (P.inf){ R=Q; return; }
    if (Q.inf){ R=P; return; }
    fe Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,Jv,r,V,T;
    fe_sqr(Z1Z1,P.Z); fe_sqr(Z2Z2,Q.Z);
    fe_mul(U1,P.X,Z2Z2); fe_mul(U2,Q.X,Z1Z1);
    fe_mul(S1,P.Y,Q.Z); fe_mul(S1,S1,Z2Z2);
    fe_mul(S2,Q.Y,P.Z); fe_mul(S2,S2,Z1Z1);
    fe_sub(H,U2,U1);
    fe_add(I,H,H); fe_sqr(I,I);
    fe_mul(Jv,H,I);
    fe_sub(r,S2,S1); fe_add(r,r,r);
    fe_mul(V,U1,I);
    fe_sqr(R.X,r); fe_sub(R.X,R.X,Jv); fe_sub(T,V,R.X); fe_sub(R.X,R.X,V);
    fe_mul(R.Y,r,T); fe_mul(T,S1,Jv); fe_add(T,T,T); fe_sub(R.Y,R.Y,T);
    fe_add(R.Z,P.Z,Q.Z); fe_sqr(R.Z,R.Z); fe_sub(R.Z,R.Z,Z1Z1); fe_sub(R.Z,R.Z,Z2Z2); fe_mul(R.Z,R.Z,H);
    R.inf=false;
}

static inline void pj_cswap(PointJ& A, PointJ& B, uint64_t bit){
    uint64_t m=(uint64_t)-(int)(bit&1u);
    for(int i=0;i<4;i++){
        uint64_t t;
        t=(A.X.v[i]^B.X.v[i])&m; A.X.v[i]^=t; B.X.v[i]^=t;
        t=(A.Y.v[i]^B.Y.v[i])&m; A.Y.v[i]^=t; B.Y.v[i]^=t;
        t=(A.Z.v[i]^B.Z.v[i])&m; A.Z.v[i]^=t; B.Z.v[i]^=t;
    }
    bool ib=B.inf, ia=A.inf; uint64_t ti=((uint64_t)ia ^ (uint64_t)ib) & m; A.inf=(bool)(((uint64_t)ia)^ti); B.inf=(bool)(((uint64_t)ib)^ti);
}

static inline void scalar_mul(PointJ& R, const PointA& P, const uint8_t k_be[32]){
    PointJ R0=INF(), R1; pj_from_affine(P,R1);
    for(int byte=0; byte<32; ++byte){
        uint8_t b=k_be[byte];
        for(int i=7;i>=0;--i){
            uint64_t bit=(uint64_t)((b>>i)&1);
            pj_cswap(R0,R1,bit);
            PointJ T; pj_add(R0,R1,T);
            PointJ D; pj_double(R0,D);
            R0=D; R1=T;
            pj_cswap(R0,R1,bit);
        }
    }
    R=R0;
}

static inline bool lift_x_even_y(PointA& R, const uint8_t x_be[32]){
    fe x=fe_from_bytes_be(x_be); fe x2,x3,y2; fe_sqr(x2,x); fe_mul(x3,x2,x);
    fe t; t.v={7,0,0,0}; fe_add(y2,x3,t);
    fe y; if(!fe_sqrt(y,y2)) return false;
    if (fe_is_odd(y)){ fe_neg(y,y); }
    R.x=x; R.y=y; R.inf=false; return true;
}
static inline void pa_neg(PointA& R, const PointA& A){ R.x=A.x; fe ny; fe_neg(ny,A.y); R.y=ny; R.inf=A.inf; }

}} // ns

// --- wNAF (w=4) + precompute de G (fast path s·G) ---
static inline bool u256_is_zero(const fe& a){ return (a.v[0]|a.v[1]|a.v[2]|a.v[3])==0; }
static inline bool u256_is_odd(const fe& a){ return (a.v[0] & 1ull)!=0ull; }
static inline uint64_t u256_lowbits(const fe& a, int bits){ return a.v[0] & ((1ull<<bits)-1ull); }
static inline void u256_sub_small(fe& a, uint64_t d){ unsigned char brr=0; brr=_subborrow_u64(0,a.v[0],d,&a.v[0]); brr=_subborrow_u64(brr,a.v[1],0,&a.v[1]); brr=_subborrow_u64(brr,a.v[2],0,&a.v[2]); brr=_subborrow_u64(brr,a.v[3],0,&a.v[3]); }
static inline void u256_add_small(fe& a, int64_t d){ unsigned char c=0; c=_addcarry_u64(0,a.v[0],(uint64_t)d,&a.v[0]); c=_addcarry_u64(c,a.v[1],(d<0)?~0ull:0ull,&a.v[1]); c=_addcarry_u64(c,a.v[2],(d<0)?~0ull:0ull,&a.v[2]); c=_addcarry_u64(c,a.v[3],(d<0)?~0ull:0ull,&a.v[3]); }
static inline void u256_rshift1(fe& a){ a.v[0]=(a.v[0]>>1)|(a.v[1]<<63); a.v[1]=(a.v[1]>>1)|(a.v[2]<<63); a.v[2]=(a.v[2]>>1)|(a.v[3]<<63); a.v[3]=(a.v[3]>>1); }

static inline int wnaf_w4(const uint8_t k_be[32], int8_t digits[300]){
    fe k = fe_from_bytes_be(k_be);
    int pos=0;
    while(!u256_is_zero(k)){
        int8_t di=0;
        if (u256_is_odd(k)){
            uint64_t u = u256_lowbits(k, 4); // [0..15]
            if (u>7) u = u - 16;             // => [-8..7]
            if ((u & 1ull)==0ull){ u = 1; }  // garante ímpar
            di = (int8_t)u;
            if (di>0) u256_sub_small(k, (uint64_t)di);
            else      u256_add_small(k, (int64_t)(-di));
        }
        digits[pos++] = di;
        u256_rshift1(k);
    }
    return pos;
}

// Precompute de G: odd multiples (1..15) para w=4
static inline void precompute_G_w4(PointA table[8]){
    PointA g = G();
    PointJ gj; pj_from_affine(g, gj);
    PointJ two; pj_double(gj, two); // 2G
    PointA a1; pa_from_jacobian(gj, a1); table[0]=a1; // 1G
    PointJ acc=gj;
    for(int i=1;i<8;i++){
        PointJ t; pj_add(acc, two, t); acc=t; PointA ai; pa_from_jacobian(acc, ai); table[i]=ai; // 3G,5G,...,15G
    }
}

// s·G via wNAF + precompute de G (w=4)
static inline void scalar_mul_base_wnaf(PointJ& R, const uint8_t k_be[32]){
    static bool init=false; static PointA T[8];
    if(!init){ precompute_G_w4(T); init=true; }
    int8_t digits[300]; int len = wnaf_w4(k_be, digits);
    R = INF();
    for(int i=len-1;i>=0;--i){
        if (!R.inf){ PointJ D; pj_double(R,D); R=D; }
        int8_t di = digits[i];
        if (di){
            int idx = (abs(di)-1)/2;
            PointA A = T[idx];
            if (di<0){ PointA N; pa_neg(N, A); A=N; }
            PointJ Aj; pj_from_affine(A, Aj);
            PointJ S; pj_add(R, Aj, S); R=S;
        }
    }
}

