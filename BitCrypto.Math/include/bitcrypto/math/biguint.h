#pragma once
#include <cstdint>
#include <cstring>
#include <array>
#ifdef _MSC_VER
#include <intrin.h>
#endif
namespace bitcrypto { namespace math {
template<size_t LIMBS> struct BigUInt{ std::array<uint64_t,LIMBS> v; inline void set0(){v.fill(0);} inline bool is0()const{for(size_t i=0;i<LIMBS;i++) if(v[i]) return false; return true;} };
using BigUInt256=BigUInt<4>; using BigUInt512=BigUInt<8>;
inline uint8_t add_cc(uint64_t a,uint64_t b,uint64_t& o){ unsigned char c=_addcarry_u64(0,a,b,&o); return c; }
inline uint8_t add_cc(uint64_t a,uint64_t b,uint8_t ci,uint64_t& o){ unsigned char c=_addcarry_u64(ci,a,b,&o); return c; }
inline uint8_t sub_bb(uint64_t a,uint64_t b,uint64_t& o){ unsigned char br=_subborrow_u64(0,a,b,&o); return br; }
inline uint8_t sub_bb(uint64_t a,uint64_t b,uint8_t bi,uint64_t& o){ unsigned char br=_subborrow_u64(bi,a,b,&o); return br; }
inline void add(const BigUInt256&A,const BigUInt256&B,BigUInt256&R,uint8_t& c){ c=0; for(size_t i=0;i<4;i++) c=add_cc(A.v[i],B.v[i],c,R.v[i]); }
inline uint8_t sub(const BigUInt256&A,const BigUInt256&B,BigUInt256&R){ uint8_t b=0; for(size_t i=0;i<4;i++) b=sub_bb(A.v[i],B.v[i],b,R.v[i]); return b; }
inline int cmp(const BigUInt256&A,const BigUInt256&B){ for(int i=3;i>=0;i--){ if(A.v[i]<B.v[i]) return -1; if(A.v[i]>B.v[i]) return 1; } return 0; }
inline void mul(const BigUInt256&A,const BigUInt256&B,BigUInt512&R){ R.v.fill(0); for(size_t i=0;i<4;i++){ unsigned __int128 c=0; for(size_t j=0;j<4;j++){ unsigned __int128 acc=(unsigned __int128)A.v[i]*(unsigned __int128)B.v[j]+(unsigned __int128)R.v[i+j]+c; R.v[i+j]=(uint64_t)acc; c=acc>>64; } R.v[i+4]+=(uint64_t)c; } }
struct Mont{ BigUInt256 N; uint64_t n0inv; BigUInt256 RR; };
inline uint64_t inv64_odd(uint64_t a){ uint64_t x=1; for(int i=0;i<6;i++){ x*= (2 - a*x); } return x; }
inline void mont_init(Mont& M,const BigUInt256& N){
    M.N=N; M.n0inv=(uint64_t)(0 - inv64_odd(N.v[0]));
    BigUInt256 r; r.set0(); r.v[0]=1;
    auto mod_add=[&](BigUInt256& X,const BigUInt256& Y){ BigUInt256 t; uint8_t c=0; add(X,Y,t,c); X=t; if(c || cmp(X,M.N)>=0){ BigUInt256 s; sub(X,M.N,s); X=s; } };
    for(int i=0;i<256;i++) mod_add(r,r); // R
    for(int i=0;i<256;i++) mod_add(r,r); // RR
    M.RR=r;
}
inline void mont_reduce(const Mont&M, BigUInt512& T, BigUInt256& R){
    BigUInt512 t=T;
    for(size_t k=0;k<4;k++){
        uint64_t m=(uint64_t)((unsigned __int128)t.v[k]*(unsigned __int128)M.n0inv);
        uint64_t carry=0;
        for(size_t j=0;j<4;j++){
            unsigned __int128 acc=(unsigned __int128)t.v[k+j]+(unsigned __int128)m*(unsigned __int128)M.N.v[j]+carry;
            t.v[k+j]=(uint64_t)acc; carry=(uint64_t)(acc>>64);
        }
        size_t idx=k+4;
        while(carry){ unsigned __int128 acc=(unsigned __int128)t.v[idx]+carry; t.v[idx]=(uint64_t)acc; carry=(uint64_t)(acc>>64); idx++; }
    }
    for(size_t i=0;i<4;i++) R.v[i]=t.v[i+4];
    if(cmp(R,M.N)>=0){ BigUInt256 s; sub(R,M.N,s); R=s; }
}
inline void to_mont(const Mont&M,const BigUInt256&A, BigUInt256& Am){ BigUInt512 tmp; mul(A,M.RR,tmp); mont_reduce(M,tmp,Am); }
inline void from_mont(const Mont&M,const BigUInt256& Am, BigUInt256& A){ BigUInt512 T; T.v.fill(0); for(int i=0;i<4;i++) T.v[i]=Am.v[i]; BigUInt256 out; mont_reduce(M,T,out); A=out; }
inline void mont_mul(const Mont&M,const BigUInt256&A,const BigUInt256&B, BigUInt256& R){ BigUInt512 T; mul(A,B,T); mont_reduce(M,T,R); }
inline void mont_sqr(const Mont&M,const BigUInt256&A, BigUInt256& R){ BigUInt512 T; mul(A,A,T); mont_reduce(M,T,R); }
}} // ns
