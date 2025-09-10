#pragma once
#include "base.h"
#include "u256.h"
namespace bitcrypto {
struct Fp{
    uint64_t v[4];
    BITCRYPTO_HD static inline Fp zero(){ return Fp{{0,0,0,0}}; }
    static constexpr uint64_t P[4] = {0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
    static constexpr uint64_t N0_PRIME = 0xD838091DD2253531ULL;
    static constexpr uint64_t RR[4] = {0x000007A2000E90A1ULL,0x0000000000000001ULL,0x0000000000000000ULL,0x0000000000000000ULL};
    static constexpr uint64_t ONE_NM[4] = {1,0,0,0};
    BITCRYPTO_HD inline static uint64_t mac64(uint64_t a,uint64_t b,uint64_t acc,uint64_t& carry){
        uint64_t hi,lo; mul64x64_128(a,b,hi,lo); uint64_t r=acc+lo; uint64_t c1=(r<acc); uint64_t r2=r+carry; uint64_t c2=(r2<r); carry=hi+c1+c2; return r2;
    }
    BITCRYPTO_HD inline static void sub_p_if_ge(uint64_t x[4]){
        uint64_t br=0; uint64_t t0=subb64(x[0],P[0],br), t1=subb64(x[1],P[1],br), t2=subb64(x[2],P[2],br), t3=subb64(x[3],P[3],br);
        uint64_t m=0-(uint64_t)(1-br); x[0]=(x[0]&~m)|(t0&m); x[1]=(x[1]&~m)|(t1&m); x[2]=(x[2]&~m)|(t2&m); x[3]=(x[3]&~m)|(t3&m);
    }
    BITCRYPTO_HD inline static void mont_mul(const uint64_t a[4], const uint64_t b[4], uint64_t r[4]){
        uint64_t T[9]={0,0,0,0,0,0,0,0,0};
        for(int i=0;i<4;i++){ uint64_t c=0; T[i+0]=mac64(a[i],b[0],T[i+0],c); T[i+1]=mac64(a[i],b[1],T[i+1],c); T[i+2]=mac64(a[i],b[2],T[i+2],c); T[i+3]=mac64(a[i],b[3],T[i+3],c);
            uint64_t before=T[i+4]; T[i+4]=T[i+4]+c; uint64_t cc=(T[i+4]<before); int k=i+5; while(cc && k<9){ before=T[k]; T[k]=T[k]+1; cc=(T[k]<before); k++; } }
        for(int i=0;i<4;i++){ uint64_t m=T[i]*N0_PRIME; uint64_t c=0; T[i+0]=mac64(m,P[0],T[i+0],c); T[i+1]=mac64(m,P[1],T[i+1],c); T[i+2]=mac64(m,P[2],T[i+2],c); T[i+3]=mac64(m,P[3],T[i+3],c);
            uint64_t before=T[i+4]; T[i+4]=T[i+4]+c; uint64_t cc=(T[i+4]<before); int k=i+5; while(cc && k<9){ before=T[k]; T[k]=T[k]+1; cc=(T[k]<before); k++; } }
        r[0]=T[4]; r[1]=T[5]; r[2]=T[6]; r[3]=T[7]; sub_p_if_ge(r);
    }
    BITCRYPTO_HD inline static Fp from_u256_nm(const U256& a){ Fp r; mont_mul(a.v, RR, r.v); return r; }
    BITCRYPTO_HD inline U256 to_u256_nm() const { uint64_t out[4]; mont_mul(v, ONE_NM, out); return U256{{out[0],out[1],out[2],out[3]}}; }
    BITCRYPTO_HD inline static Fp add(const Fp& a,const Fp& b){ Fp r; uint64_t c=0; r.v[0]=addc64(a.v[0],b.v[0],c); r.v[1]=addc64(a.v[1],b.v[1],c); r.v[2]=addc64(a.v[2],b.v[2],c); r.v[3]=addc64(a.v[3],b.v[3],c); sub_p_if_ge(r.v); return r; }
    BITCRYPTO_HD inline static Fp sub(const Fp& a,const Fp& b){ Fp r; uint64_t br=0; r.v[0]=subb64(a.v[0],b.v[0],br); r.v[1]=subb64(a.v[1],b.v[1],br); r.v[2]=subb64(a.v[2],b.v[2],br); r.v[3]=subb64(a.v[3],b.v[3],br); if(br){ uint64_t c=0; r.v[0]=addc64(r.v[0],P[0],c); r.v[1]=addc64(r.v[1],P[1],c); r.v[2]=addc64(r.v[2],P[2],c); r.v[3]=addc64(r.v[3],P[3],c);} return r; }
    BITCRYPTO_HD inline static Fp mul(const Fp& a,const Fp& b){ Fp r; mont_mul(a.v,b.v,r.v); return r; }
    BITCRYPTO_HD inline static Fp sqr(const Fp& a){ return mul(a,a); }
    BITCRYPTO_HD inline static Fp pow(const Fp& a,const U256& e){ Fp base=a; Fp res=from_u256_nm(U256::one()); for(int i=255;i>=0;i--){ res=sqr(res); uint64_t w=e.v[i/64]; uint64_t bit=(w>>(i%64))&1ULL; Fp tmp=mul(res,base); uint64_t m=0-bit; for(int j=0;j<4;j++){ uint64_t x=(res.v[j]^tmp.v[j])&m; res.v[j]^=x; } } return res; }
    BITCRYPTO_HD inline static Fp inv(const Fp& a){
        U256 e{{0xFFFFFFFEFFFFFC2DULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL}};
        return pow(a,e);
    }
    // sqrt em Fp: p % 4 == 3 ⇒ sqrt(a) = a^{(p+1)/4}
    BITCRYPTO_HD inline static Fp sqrt(const Fp& a){
        U256 e{{0xFFFFFFFFBFFFFF0CULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x3FFFFFFFFFFFFFFFULL}}; // (p+1)/4
        return pow(a, e);
    }
};
}
