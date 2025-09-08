#pragma once
#include "biguint.h"
namespace bitcrypto { namespace math {
static inline BigUInt256 const_p(){ BigUInt256 p; p.v={0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL}; return p; }
static inline BigUInt256 const_n(){ BigUInt256 n; n.v={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL}; return n; }
struct FieldCtx{ Mont M; FieldCtx(){ mont_init(M,const_p()); } };
struct ScalarCtx{ Mont M; ScalarCtx(){ mont_init(M,const_n()); } };
inline void fe_add(const FieldCtx&C,const BigUInt256&a,const BigUInt256&b, BigUInt256&r){ BigUInt256 t; uint8_t c=0; add(a,b,t,c); if(c || cmp(t,C.M.N)>=0){ BigUInt256 s; sub(t,C.M.N,s); r=s; } else r=t; }
inline void fe_sub(const FieldCtx&C,const BigUInt256&a,const BigUInt256&b, BigUInt256&r){ if(sub(a,b,r)){ BigUInt256 t; sub(C.M.N,r,t); r=t; } }
inline void fe_mul(const FieldCtx&C,const BigUInt256&a,const BigUInt256&b, BigUInt256&r){ BigUInt256 am,bm,rm; to_mont(C.M,a,am); to_mont(C.M,b,bm); mont_mul(C.M,am,bm,rm); from_mont(C.M,rm,r); }
inline void fe_sqr(const FieldCtx&C,const BigUInt256&a, BigUInt256&r){ BigUInt256 am,rm; to_mont(C.M,a,am); mont_sqr(C.M,am,rm); from_mont(C.M,rm,r); }
inline void fe_inv(const FieldCtx&C,const BigUInt256&a, BigUInt256&r){
    BigUInt256 e=C.M.N; // p
    BigUInt256 two; two.v={2,0,0,0}; (void)sub(e,two,e); // e=p-2
    BigUInt256 base=a, acc; acc.v={1,0,0,0};
    for(int i=0;i<256;i++){ if((e.v[i/64]>>(i%64))&1ULL){ fe_mul(C,acc,base,acc);} fe_sqr(C,base,base); }
    r=acc;
}
}} // ns
