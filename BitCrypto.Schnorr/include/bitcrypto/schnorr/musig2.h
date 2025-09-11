#pragma once
#include <vector>
#include <array>
#include <algorithm>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/encoding/taproot.h>

// Inspirado na implementação MuSig2 do libsecp256k1; analisamos
// a biblioteca de referência para adaptar agregação de chaves,
// de *nonces* e de assinaturas parciais via coeficientes hash e
// reutilizando o motor MSM Pippenger.

namespace bitcrypto { namespace schnorr {

// Agrega chaves públicas x-only em um único ponto utilizando
// os coeficientes determinísticos de MuSig2.
static inline bool musig2_key_aggregate(const std::vector<ECPointA>& pubs,
                                        ECPointA& out,
                                        void* ctx=nullptr){
    size_t n = pubs.size();
    if(n==0){ out = ECPointA{Fp::zero(),Fp::zero(),true}; return false; }
    if(n==1){ out = pubs[0]; return true; }

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

    // Acumula \sum mu_i * P_i com multiplicações escalares simples
    ECPointJ acc = Secp256k1::scalar_mul(scalars[0], pts[0]);
    for(size_t i=1;i<n;i++){
        ECPointJ tmp = Secp256k1::scalar_mul(scalars[i], pts[i]);
        acc = Secp256k1::add(acc, tmp);
    }
    out = Secp256k1::to_affine(acc);
    return !out.infinity;
}

// Soma *nonces* de forma eficiente usando o motor MSM com
// coeficientes unitários (1).  Segue a abordagem do libsecp256k1
// para acumular R = \Sigma R_i em validações MuSig2.
static inline bool musig2_nonce_aggregate(const std::vector<ECPointA>& nonces,
                                          ECPointA& out,
                                          void* ctx=nullptr){
    size_t n = nonces.size();
    if(n==0){ out = ECPointA{Fp::zero(),Fp::zero(),true}; return false; }
    ECPointJ acc = Secp256k1::to_jacobian(nonces[0]);
    for(size_t i=1;i<n;i++){
        acc = Secp256k1::add(acc, Secp256k1::to_jacobian(nonces[i]));
    }
    out = Secp256k1::to_affine(acc);
    return !out.infinity;
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

// Combina agregação de chave, *nonces* e assinaturas parciais
// produzindo a assinatura Schnorr final r||s.
static inline bool musig2_sign(const std::vector<ECPointA>& pubs,
                               const std::vector<ECPointA>& nonces,
                               const std::vector<U256>& parts,
                               ECPointA& agg_key,
                               uint8_t sig[64],
                               void* ctx=nullptr){
    if (pubs.empty() || nonces.empty() || parts.empty()) return false;
    if (pubs.size()!=nonces.size() || pubs.size()!=parts.size()) return false;
    ECPointA R; U256 s;
    if(!musig2_key_aggregate(pubs, agg_key, ctx)) return false;
    // Garante chave agregada com coordenada Y par
    {
        uint8_t px[32]; bool neg=false; agg_key = encoding::normalize_even_y(agg_key, px, neg);
    }
    if(!musig2_nonce_aggregate(nonces, R, ctx)) return false;
    if(!musig2_partial_aggregate(parts, s)) return false;
    // Normaliza R para Y par e ajusta s se necessário
    uint8_t rx[32]; bool rneg=false; R = encoding::normalize_even_y(R, rx, rneg);
    if(rneg){
        Fn sf = Fn::sub(Fn::zero(), Fn::from_u256_nm(s));
        s = sf.to_u256_nm();
    }
    R.x.to_u256_nm().to_be32(sig);
    s.to_be32(sig+32);
    return true;
}

// Recalcula o desafio e verifica a equação do grupo sG = R + eP.
static inline bool musig2_verify(const std::vector<ECPointA>& pubs,
                                 const std::vector<ECPointA>& nonces,
                                 const std::vector<U256>& parts,
                                 const uint8_t msg[32],
                                 void* ctx=nullptr){
    if (pubs.empty() || nonces.empty() || parts.empty()) return false;
    if (pubs.size()!=nonces.size() || pubs.size()!=parts.size()) return false;
    ECPointA P,R;
    if(!musig2_key_aggregate(pubs, P, ctx)) return false;
    if(!musig2_nonce_aggregate(nonces, R, ctx)) return false;
    U256 s; if(!musig2_partial_aggregate(parts, s)) return false;
    uint8_t rx[32]; bool rneg=false; R = encoding::normalize_even_y(R, rx, rneg);
    if(rneg){ Fn sf = Fn::sub(Fn::zero(), Fn::from_u256_nm(s)); s = sf.to_u256_nm(); }
    uint8_t px[32]; bool pneg=false; P = encoding::normalize_even_y(P, px, pneg); if(pneg) return false;
    uint8_t chal[96]; std::memcpy(chal, rx, 32); std::memcpy(chal+32, px, 32); std::memcpy(chal+64, msg, 32);
    uint8_t e32[32]; hash::sha256_tagged("BIP0340/challenge", chal, sizeof(chal), e32);
    U256 e = U256::from_be32(e32); Secp256k1::scalar_mod_n(e);
    ECPointJ sG = Secp256k1::scalar_mul(s, Secp256k1::G());
    ECPointJ eP = Secp256k1::scalar_mul(e, P);
    ECPointJ rhs = Secp256k1::add(Secp256k1::to_jacobian(R), eP);
    if (Secp256k1::is_infinity(sG) || Secp256k1::is_infinity(rhs)) return false;
    ECPointA sGa = Secp256k1::to_affine(sG);
    ECPointA rhsa = Secp256k1::to_affine(rhs);
    if (sGa.infinity || rhsa.infinity) return false;
    return (sGa.x.v[0]==rhsa.x.v[0] && sGa.x.v[1]==rhsa.x.v[1] &&
            sGa.x.v[2]==rhsa.x.v[2] && sGa.x.v[3]==rhsa.x.v[3] &&
            sGa.y.v[0]==rhsa.y.v[0] && sGa.y.v[1]==rhsa.y.v[1] &&
            sGa.y.v[2]==rhsa.y.v[2] && sGa.y.v[3]==rhsa.y.v[3]);
}

}} // namespaces

