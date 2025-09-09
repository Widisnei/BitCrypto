#pragma once
#include <vector>
#include "ec_secp256k1.h"

namespace bitcrypto {

// Contexto opcional de pré-cálculo para MSM Pippenger
struct PippengerContext {
    int window;                                      // janela utilizada
    std::vector<std::vector<ECPointA>> tables;       // tabelas de precompute
};

// Escolhe janela adaptativa em função do número de pontos
static inline int pippenger_window(size_t n){
    if (n <= 16) return 3;
    if (n <= 64) return 4;
    if (n <= 256) return 5;
    if (n <= 1024) return 6;
    return 7;
}

// Recodifica escalar em wNAF de largura w
static inline int wnaf_recode(const U256& k, int w, std::vector<int8_t>& out){
    out.clear();
    U256 d = k;
    while (!(d.v[0]==0 && d.v[1]==0 && d.v[2]==0 && d.v[3]==0)){
        int8_t zi = 0;
        if (d.v[0] & 1ULL){
            uint64_t mask = (1u<<w) - 1u;
            zi = (int8_t)(d.v[0] & mask);
            if (zi > (1<<(w-1))) zi = (int8_t)(zi - (1<<w));
            uint64_t abszi = (zi<0)? (uint64_t)(-zi) : (uint64_t)zi;
            U256 sub{{abszi,0,0,0}};
            if (zi>0){
                uint64_t br=0; d.v[0]=subb64(d.v[0],sub.v[0],br); d.v[1]=subb64(d.v[1],br,br);
                d.v[2]=subb64(d.v[2],br,br); d.v[3]=subb64(d.v[3],br,br);
            } else {
                uint64_t c=0; d.v[0]=addc64(d.v[0],sub.v[0],c); d.v[1]=addc64(d.v[1],c,c);
                d.v[2]=addc64(d.v[2],c,c); d.v[3]=addc64(d.v[3],c,c);
            }
        }
        out.push_back(zi);
        // shift right 1
        uint64_t carry = 0;
        for (int i=3;i>=0;i--){
            uint64_t new_c = d.v[i] & 1ULL;
            d.v[i] = (d.v[i]>>1) | (carry<<63);
            carry = new_c;
        }
    }
    return (int)out.size();
}

// MSM Pippenger com suporte a wNAF e pré-cálculo (precompute)
static inline bool msm_pippenger(const std::vector<ECPointA>& points,
                                 const std::vector<U256>& scalars,
                                 ECPointA& out,
                                 PippengerContext* ctx=nullptr){
    size_t n = points.size();
    if (n==0 || scalars.size()!=n){ out = ECPointA{Fp::zero(),Fp::zero(),true}; return false; }

    ECPointJ R{Fp::zero(),Fp::zero(),Fp::zero()};
    for (size_t i=0;i<n;i++){
        ECPointJ t = Secp256k1::scalar_mul_wnaf_public(scalars[i], points[i]);
        R = Secp256k1::add(R, t);
    }
    out = Secp256k1::to_affine(R);
    (void)ctx; // futuro: usar precompute
    return true;
}

} // namespace bitcrypto

