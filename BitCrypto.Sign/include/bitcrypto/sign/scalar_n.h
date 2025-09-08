#pragma once
#include "../../BitCrypto.Core/include/bitcrypto/base.h"
#include "../../BitCrypto.Core/include/bitcrypto/u256.h"
namespace bitcrypto { namespace sign {
struct Fn{
    uint64_t v[4];
    static constexpr uint64_t N[4] = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    static constexpr uint64_t N0_PRIME = 0x4B0DFF665588B13FULL; // -N^{-1} mod 2^64
    static constexpr uint64_t RR[4] = {0x896CF21467D7D140ULL,0x741496C20E7CF878ULL,0xE697F5E45BCD07C6ULL,0x9D671CD581C69BC5ULL}; // R^2 mod N
    BITCRYPTO_HD static inline Fn zero(){ return Fn{{0,0,0,0}}; }
    BITCRYPTO_HD static inline uint64_t mac64(uint64_t a,uint64_t b,uint64_t acc,uint64_t& carry){ uint64_t hi,lo; mul64x64_128(a,b,hi,lo); uint64_t r=acc+lo; uint64_t c1=(r<acc); uint64_t r2=r+carry; uint64_t c2=(r2<r); carry=hi+c1+c2; return r2; }
    BITCRYPTO_HD static inline void sub_n_if_ge(uint64_t x[4]){
        const uint64_t* M=N; uint64_t br=0;
        uint64_t t0=subb64(x[0],M[0],br), t1=subb64(x[1],M[1],br), t2=subb64(x[2],M[2],br), t3=subb64(x[3],M[3],br);
        uint64_t m=0-(uint64_t)(1-br); x[0]=(x[0]&~m)|(t0&m); x[1]=(x[1]&~m)|(t1&m); x[2]=(x[2]&~m)|(t2&m); x[3]=(x[3]&~m)|(t3&m);
    }
    BITCRYPTO_HD static inline void mont_mul(const uint64_t a[4], const uint64_t b[4], uint64_t r[4]){
        uint64_t T[8]={0,0,0,0,0,0,0,0};
        for(int i=0;i<4;i++){ uint64_t c=0; T[i+0]=mac64(a[i],b[0],T[i+0],c); T[i+1]=mac64(a[i],b[1],T[i+1],c); T[i+2]=mac64(a[i],b[2],T[i+2],c); T[i+3]=mac64(a[i],b[3],T[i+3],c);
            uint64_t before=T[i+4]; T[i+4]=T[i+4]+c; uint64_t cc=(T[i+4]<before); int k=i+5; while(cc){ before=T[k]; T[k]=T[k]+1; cc=(T[k]<before); k++; } }
        for(int i=0;i<4;i++){ uint64_t m=T[i]*N0_PRIME; uint64_t c=0; T[i+0]=mac64(m,N[0],T[i+0],c); T[i+1]=mac64(m,N[1],T[i+1],c); T[i+2]=mac64(m,N[2],T[i+2],c); T[i+3]=mac64(m,N[3],T[i+3],c);
            uint64_t before=T[i+4]; T[i+4]=T[i+4]+c; uint64_t cc=(T[i+4]<before); int k=i+5; while(cc){ before=T[k]; T[k]=T[k]+1; cc=(T[k]<before); k++; } }
        r[0]=T[4]; r[1]=T[5]; r[2]=T[6]; r[3]=T[7]; sub_n_if_ge(r);
    }
    BITCRYPTO_HD static inline Fn from_u256_nm(const U256& a){ Fn r; mont_mul(a.v, RR, r.v); return r; }
    BITCRYPTO_HD inline U256 to_u256_nm() const { uint64_t one[4]={1,0,0,0}; uint64_t out[4]; mont_mul(v, one, out); return U256{{out[0],out[1],out[2],out[3]}}; }
    BITCRYPTO_HD static inline Fn add(const Fn& a,const Fn& b){ Fn r; uint64_t c=0; r.v[0]=addc64(a.v[0],b.v[0],c); r.v[1]=addc64(a.v[1],b.v[1],c); r.v[2]=addc64(a.v[2],b.v[2],c); r.v[3]=addc64(a.v[3],b.v[3],c); sub_n_if_ge(r.v); return r; }
    BITCRYPTO_HD static inline Fn sub(const Fn& a,const Fn& b){ Fn r; uint64_t br=0; r.v[0]=subb64(a.v[0],b.v[0],br); r.v[1]=subb64(a.v[1],b.v[1],br); r.v[2]=subb64(a.v[2],b.v[2],br); r.v[3]=subb64(a.v[3],b.v[3],br);
        if(br){ uint64_t c=0; r.v[0]=addc64(r.v[0],N[0],c); r.v[1]=addc64(r.v[1],N[1],c); r.v[2]=addc64(r.v[2],N[2],c); r.v[3]=addc64(r.v[3],N[3],c);} return r; }
    BITCRYPTO_HD static inline Fn mul(const Fn& a,const Fn& b){ Fn r; mont_mul(a.v,b.v,r.v); return r; }
    BITCRYPTO_HD static inline Fn pow(const Fn& a, const U256& e){ Fn base=a; Fn res = from_u256_nm(U256::one()); for(int i=255;i>=0;i--){ res=mul(res,res); uint64_t w=e.v[i/64]; uint64_t bit=(w>>(i%64))&1ULL; Fn tmp=mul(res,base); uint64_t m=0-bit; for(int j=0;j<4;j++){ uint64_t x=(res.v[j]^tmp.v[j])&m; res.v[j]^=x; } } return res; }
    BITCRYPTO_HD static inline Fn inv(const Fn& a){ // N é primo ⇒ a^(N-2)
        U256 e{{0xBFD25E8CD036413FULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL}}; // N-2
        return pow(a,e);
    }
    static inline bool geq_n(const U256& a){ const uint64_t* M=N; if (a.v[3]!=M[3]) return a.v[3]>M[3]; if (a.v[2]!=M[2]) return a.v[2]>M[2]; if (a.v[1]!=M[1]) return a.v[1]>M[1]; return a.v[0]>=M[0]; }
    static inline void mod_n(U256& a){ // reduz para [0, N-1]
        const uint64_t* M=N; uint64_t br=0; uint64_t t0=subb64(a.v[0],M[0],br), t1=subb64(a.v[1],M[1],br), t2=subb64(a.v[2],M[2],br), t3=subb64(a.v[3],M[3],br);
        uint64_t m=0-(uint64_t)(1-br); a.v[0]=(a.v[0]&~m)|(t0&m); a.v[1]=(a.v[1]&~m)|(t1&m); a.v[2]=(a.v[2]&~m)|(t2&m); a.v[3]=(a.v[3]&~m)|(t3&m);
    }
};
}}