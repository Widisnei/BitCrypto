#pragma once
#include <vector>
#include "ec_secp256k1.h"
#include "msm_pippenger.h" // reutiliza wNAF
#include "mod_n.h"

// Baseado nas técnicas de endomorfismo e Shamir presentes no
// libsecp256k1; estudamos a biblioteca de referência para obter as
// constantes e a estratégia de decomposição de escalar.
namespace bitcrypto {

// Constantes do endomorphism lambda
static constexpr U256 LAMBDA{{0xc05c30e05363ad4cULL,0x8812645aa5261c02ULL,0x20816678122e22eaULL,0x1b23bd72df02967cULL}};
static constexpr U256 MINUS_B1{{0x0ULL,0x0ULL,0x010e8828e4437ed6ULL,0x0abfe4c36f547fa9ULL}};
static constexpr U256 MINUS_B2{{0xffffffffffffffffULL,0xfffffffeffffffffULL,0x0774346d8a280ac5ULL,0x3db1562cd765cda8ULL}};
static constexpr U256 G1{{0xa7d46bcd3086d221ULL,0x9284eb15e86c90e4ULL,0x71e8ca7f3daa8a14ULL,0x45dbb031e893209aULL}};
static constexpr U256 G2{{0x010e8828e4437ed6ULL,0x0abfe4c46f547fa9ULL,0x9df506c6221208acULL,0x8ac47f711571b4aeULL}};

// Multiplica dois U256 produzindo 512 bits (little-end)
static inline void mul256(const U256& a,const U256& b,uint64_t r[8]){
    for(int i=0;i<8;i++) r[i]=0;
    for(int i=0;i<4;i++){
        unsigned __int128 carry=0;
        for(int j=0;j<4;j++){
            unsigned __int128 prod=(unsigned __int128)a.v[i]*b.v[j];
            unsigned __int128 sum=prod + r[i+j] + carry;
            r[i+j]=(uint64_t)sum;
            carry=sum>>64;
        }
        int k=i+4;
        while(carry){
            unsigned __int128 sum=(unsigned __int128)r[k]+carry;
            r[k]=(uint64_t)sum;
            carry=sum>>64;
            k++;
        }
    }
}

// (a*b + 2^{shift-1}) >> shift
static inline void mul_shift_round(U256& out,const U256& a,const U256& b,unsigned shift){
    uint64_t l[8]; mul256(a,b,l);
    unsigned idx=(shift-1)>>6; unsigned bit=(shift-1)&63;
    unsigned __int128 t=(unsigned __int128)l[idx] + (1ULL<<bit);
    l[idx]=(uint64_t)t; uint64_t c=t>>64; int k=idx+1; while(c && k<8){ unsigned __int128 t2=(unsigned __int128)l[k]+c; l[k]=(uint64_t)t2; c=t2>>64; k++; }
    unsigned shiftlimbs=shift>>6; unsigned shiftlow=shift&63; unsigned shifthigh=64-shiftlow;
    uint64_t r0=0,r1=0,r2=0,r3=0;
    if(shiftlow==0){
        if(shiftlimbs<8) r0=l[shiftlimbs];
        if(shiftlimbs+1<8) r1=l[shiftlimbs+1];
        if(shiftlimbs+2<8) r2=l[shiftlimbs+2];
        if(shiftlimbs+3<8) r3=l[shiftlimbs+3];
    } else {
        if(shiftlimbs<8) r0=(l[shiftlimbs]>>shiftlow);
        if(shiftlimbs+1<8){ r0 |= l[shiftlimbs+1]<<shifthigh; r1 = l[shiftlimbs+1]>>shiftlow; }
        if(shiftlimbs+2<8){ r1 |= l[shiftlimbs+2]<<shifthigh; r2 = l[shiftlimbs+2]>>shiftlow; }
        if(shiftlimbs+3<8){ r2 |= l[shiftlimbs+3]<<shifthigh; r3 = l[shiftlimbs+3]>>shiftlow; }
        if(shiftlimbs+4<8) r3 |= l[shiftlimbs+4]<<shifthigh;
    }
    out = U256{{r0,r1,r2,r3}};
}

// Decomposição de escalar via endomorfismo lambda
static inline void split_scalar_lambda(const U256& k,U256& r1,U256& r2){
    U256 c1u,c2u; mul_shift_round(c1u,k,G1,384); mul_shift_round(c2u,k,G2,384);
    Fn c1 = Fn::from_u256_nm(c1u); Fn c2 = Fn::from_u256_nm(c2u);
    Fn mb1 = Fn::from_u256_nm(MINUS_B1); Fn mb2 = Fn::from_u256_nm(MINUS_B2);
    Fn lambda = Fn::from_u256_nm(LAMBDA); Fn kf = Fn::from_u256_nm(k);
    Fn r2f = Fn::add(Fn::mul(c1,mb1), Fn::mul(c2,mb2));
    Fn r1f = Fn::sub(kf, Fn::mul(r2f, lambda));
    r1 = r1f.to_u256_nm(); r2 = r2f.to_u256_nm();
}

// Shamir's trick: calcula a*P + b*G reutilizando MSM Pippenger
static inline bool shamir_trick(const ECPointA& P,const U256& a,const U256& b,ECPointA& out){
    if(P.infinity) { out = ECPointA{Fp::zero(),Fp::zero(),true}; return false; }
    std::vector<ECPointA> pts{P, Secp256k1::G()};
    std::vector<U256> sc{a, b};
    PippengerContext ctx; // utiliza precompute interno
    return msm_pippenger(pts, sc, out, &ctx);
}

} // namespace bitcrypto

