#pragma once
#include <vector>
#include <array>
#include <algorithm>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/msm_pippenger.h>
#include <bitcrypto/mod_n.h>

// Inspirado na implementação MuSig2 do libsecp256k1; analisamos
// a biblioteca de referência para adaptar agregação de chaves,
// de *nonces* e de assinaturas parciais via coeficientes hash e
// reutilizando o motor MSM Pippenger.

namespace bitcrypto { namespace schnorr {

// Agrega chaves públicas x-only em um único ponto utilizando
// os coeficientes determinísticos de MuSig2.
static inline bool musig2_key_aggregate(const std::vector<ECPointA>& pubs,
                                        ECPointA& out,
                                        PippengerContext* ctx=nullptr){
    size_t n = pubs.size();
    if(n==0){ out = ECPointA{Fp::zero(),Fp::zero(),true}; return false; }

    // Extração dos x-coords em big-endian para hashing
    std::vector<std::array<uint8_t,32>> xonly(n);
    for(size_t i=0;i<n;i++){
        U256 xi = pubs[i].x.to_u256_nm();
        xi.to_be32(xonly[i].data());
    }
    // Ordena para obter agregação determinística
    std::vector<size_t> order(n);
    for(size_t i=0;i<n;i++) order[i]=i;
    std::sort(order.begin(), order.end(), [&](size_t a,size_t b){
        return std::memcmp(xonly[a].data(), xonly[b].data(), 32) < 0;
    });

    // ell = SHA256(concat x-only)
    std::vector<uint8_t> concat; concat.reserve(32*n);
    for(size_t idx: order){
        concat.insert(concat.end(), xonly[idx].begin(), xonly[idx].end());
    }
    uint8_t ell[32]; hash::sha256(concat.data(), concat.size(), ell);

    // Coeficientes mu_i = SHA256(ell || x_i)
    std::vector<U256> scalars; scalars.reserve(n);
    std::vector<ECPointA> pts; pts.reserve(n);
    for(size_t idx: order){
        uint8_t buf[64];
        std::memcpy(buf, ell, 32);
        std::memcpy(buf+32, xonly[idx].data(), 32);
        uint8_t mu32[32]; hash::sha256(buf, 64, mu32);
        U256 mu = U256::from_be32(mu32);
        Fn muf = Fn::from_u256_nm(mu);
        scalars.push_back(muf.to_u256_nm());
        pts.push_back(pubs[idx]);
    }

    return msm_pippenger(pts, scalars, out, ctx);
}

// Soma *nonces* de forma eficiente usando o motor MSM com
// coeficientes unitários (1).  Segue a abordagem do libsecp256k1
// para acumular R = \Sigma R_i em validações MuSig2.
static inline bool musig2_nonce_aggregate(const std::vector<ECPointA>& nonces,
                                          ECPointA& out,
                                          PippengerContext* ctx=nullptr){
    size_t n = nonces.size();
    if(n==0){ out = ECPointA{Fp::zero(),Fp::zero(),true}; return false; }
    std::vector<U256> ones(n, U256::one());
    return msm_pippenger(nonces, ones, out, ctx);
}

// Combina assinaturas parciais s_i retornando s = \Sigma s_i (mod n).
// Esta soma modular utiliza o campo Fn para garantir redução correta.
static inline bool musig2_partial_aggregate(const std::vector<U256>& parts,
                                            U256& out){
    size_t n = parts.size();
    if(n==0){ out = U256::zero(); return false; }
    Fn acc = Fn::zero();
    for(const U256& s : parts){
        acc = Fn::add(acc, Fn::from_u256_nm(s));
    }
    out = acc.to_u256_nm();
    return true;
}

}} // namespaces

