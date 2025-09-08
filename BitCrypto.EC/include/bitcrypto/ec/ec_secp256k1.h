#pragma once
#include "../math/biguint.h"
#include "../math/fe_sc.h"
namespace bitcrypto { namespace ec {
using namespace bitcrypto::math;
struct PointJac{ BigUInt256 X,Y,Z; bool infinity=false; };
static inline void fe_set1(BigUInt256&a){ a.v={1,0,0,0}; } static inline void fe_set0(BigUInt256&a){ a.v={0,0,0,0}; }
inline void point_double(const FieldCtx&F,const PointJac&P,PointJac&R){
    if(P.infinity){ R=P; return; }
    BigUInt256 XX,YY,YYYY,S,M,tmp,X3,Y3,Z3;
    fe_sqr(F,P.X,XX); fe_sqr(F,P.Y,YY); fe_sqr(F,YY,YYYY);
    fe_mul(F,P.X,YY,S); fe_add(F,S,S,S); fe_add(F,S,S,S);
    fe_add(F,XX,XX,M); fe_add(F,M,XX,M); // M=3*XX
    fe_sqr(F,M,X3);
    fe_add(F,S,S,tmp); fe_sub(F,X3,tmp,X3);
    fe_sub(F,S,X3,tmp); fe_mul(F,M,tmp,Y3);
    fe_add(F,YYYY,YYYY,tmp); fe_add(F,tmp,tmp,tmp); fe_sub(F,Y3,tmp,Y3);
    fe_mul(F,P.Y,P.Z,Z3); fe_add(F,Z3,Z3,Z3);
    R.X=X3; R.Y=Y3; R.Z=Z3; R.infinity=false;
}
inline void point_add_mixed(const FieldCtx&F,const PointJac&P,const BigUInt256&xQ,const BigUInt256&yQ,PointJac&R){
    if(P.infinity){ R.X=xQ; R.Y=yQ; fe_set1(R.Z); R.infinity=false; return; }
    BigUInt256 Z2,Z3,U2,S2,H,I,J,r,V,X3,Y3,Zp,tmp;
    fe_sqr(F,P.Z,Z2); fe_mul(F,xQ,Z2,U2); fe_mul(F,Z2,P.Z,Z3); fe_mul(F,yQ,Z3,S2);
    fe_sub(F,U2,P.X,H); fe_sub(F,S2,P.Y,r); fe_add(F,r,r,r);
    if(H.is0() && r.is0()){ point_double(F,P,R); return; }
    fe_add(F,H,H,I); fe_sqr(F,I,I); fe_mul(F,H,I,J); fe_mul(F,P.X,I,V);
    fe_sqr(F,r,X3); fe_sub(F,X3,J,X3); fe_add(F,V,V,tmp); fe_sub(F,X3,tmp,X3);
    fe_sub(F,V,X3,tmp); fe_mul(F,r,tmp,Y3); fe_mul(F,P.Y,J,tmp); fe_add(F,tmp,tmp,tmp); fe_sub(F,Y3,tmp,Y3);
    fe_add(F,P.Z,H,Zp); fe_sqr(F,Zp,Zp); fe_sqr(F,P.Z,tmp); fe_sub(F,Zp,tmp,Zp); fe_sub(F,Zp,I,Zp);
    R.X=X3; R.Y=Y3; R.Z=Zp; R.infinity=false;
}
inline void ladder(const FieldCtx&F,const BigUInt256&k,const BigUInt256&xG,const BigUInt256&yG,PointJac&R){
    PointJac R0; R0.infinity=true; PointJac R1; R1.X=xG; R1.Y=yG; fe_set1(R1.Z); R1.infinity=false;
    for(int i=255;i>=0;i--){ uint64_t bit=(k.v[i/64]>>(i%64))&1ULL; if(bit==0){ point_add_mixed(F,R0,R1.X,R1.Y,R1); point_double(F,R0,R0);} else { point_add_mixed(F,R1,R0.X,R0.Y,R0); point_double(F,R1,R1);} }
    R=R0;
}
static inline BigUInt256 Gx(){ BigUInt256 x; x.v={0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL}; return x; }
static inline BigUInt256 Gy(){ BigUInt256 y; y.v={0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL}; return y; }
}} // ns
