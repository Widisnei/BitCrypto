#pragma once
#include <vector>
#include "ec_secp256k1.h"

namespace bitcrypto {

// Contexto opcional de pré-cálculo para MSM Pippenger
struct PippengerContext {
    int window = 0;                                  // janela utilizada
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

// Recodifica escalar em wNAF de largura w (entrada pública; não const-time)
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

    int w = pippenger_window(n);
    int WSIZE = 1<<(w-2); // número de buckets (somente ímpares)

    // Constrói ou reutiliza tabelas de precompute (precompute)
    std::vector<std::vector<ECPointA>> local_tables;
    std::vector<std::vector<ECPointA>>* tables = &local_tables;
    if (ctx){
        if ((int)ctx->window != w || ctx->tables.size()!=n){
            ctx->window = w;
            ctx->tables.assign(n, std::vector<ECPointA>(WSIZE));
            for (size_t i=0;i<n;i++){
                ctx->tables[i][0] = points[i];
                ECPointJ twoP = Secp256k1::dbl(Secp256k1::to_jacobian(points[i]));
                ECPointJ acc = Secp256k1::to_jacobian(points[i]);
                for (int j=1;j<WSIZE;j++){
                    acc = Secp256k1::add(acc, twoP);
                    ctx->tables[i][j] = Secp256k1::to_affine(acc);
                }
            }
        }
        tables = &ctx->tables;
    } else {
        local_tables.assign(n, std::vector<ECPointA>(WSIZE));
        for (size_t i=0;i<n;i++){
            local_tables[i][0] = points[i];
            ECPointJ twoP = Secp256k1::dbl(Secp256k1::to_jacobian(points[i]));
            ECPointJ acc = Secp256k1::to_jacobian(points[i]);
            for (int j=1;j<WSIZE;j++){
                acc = Secp256k1::add(acc, twoP);
                local_tables[i][j] = Secp256k1::to_affine(acc);
            }
        }
    }

    // wNAF recoding de todos os escalares
    std::vector<std::vector<int8_t>> wnafs(n);
    int max_len = 0;
    for (size_t i=0;i<n;i++){
        int len = wnaf_recode(scalars[i], w, wnafs[i]);
        if (len > max_len) max_len = len;
    }

    ECPointJ R{Fp::zero(),Fp::zero(),Fp::zero()};
    for (int pos = max_len-1; pos >= 0; --pos){
        R = Secp256k1::dbl(R);
        std::vector<ECPointJ> buckets(WSIZE, ECPointJ{Fp::zero(),Fp::zero(),Fp::zero()});
        for (size_t i=0;i<n;i++){
            int8_t digit = (pos < (int)wnafs[i].size()) ? wnafs[i][pos] : 0;
            if (digit){
                int idx = (abs(digit)-1)/2;
                ECPointA T = (*tables)[i][idx];
                if (digit < 0){ T.y = Fp::sub(Fp::zero(), T.y); }
                buckets[idx] = Secp256k1::add(buckets[idx], Secp256k1::to_jacobian(T));
            }
        }
        ECPointJ acc{Fp::zero(),Fp::zero(),Fp::zero()};
        for (int i=WSIZE-1;i>0;--i){
            acc = Secp256k1::add(acc, buckets[i]);
            R = Secp256k1::add(R, acc);
        }
        if (!Secp256k1::is_infinity(buckets[0])){
            R = Secp256k1::add(R, buckets[0]);
        }
    }

    out = Secp256k1::to_affine(R);
    return true;
}

} // namespace bitcrypto

