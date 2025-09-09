#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/ec_parse.h>
#include "scalar_n.h"

namespace bitcrypto { namespace sign {

inline void xonly_from_point(const bitcrypto::ECPointA& A, uint8_t x32[32], bool& is_odd){
    bitcrypto::U256 y = A.y.to_u256_nm();
    is_odd = (y.v[0] & 1ULL) != 0ULL;
    bitcrypto::U256 x = A.x.to_u256_nm(); x.to_be32(x32);
}

// BIP-340 Schnorr sign (aux32 pode ser nullptr ⇒ usa zeros)
inline bool schnorr_sign(const uint8_t priv32[32], const uint8_t msg32[32], uint8_t sig64[64], const uint8_t* aux32=nullptr){
    using namespace bitcrypto;
    using namespace bitcrypto::hash;
    U256 d = U256::from_be32(priv32); if ((d.v[0]|d.v[1]|d.v[2]|d.v[3])==0ULL || sign::Fn::geq_n(d)) return false;
    // P = d*G
    ECPointA P = Secp256k1::to_affine(Secp256k1::scalar_mul(d, Secp256k1::G()));
    uint8_t px[32]; bool Py_odd=false; xonly_from_point(P, px, Py_odd);
    // d' = d (even Y) or n - d (odd Y)
    U256 dprime = d;
    if (Py_odd){
        const uint64_t* N = sign::Fn::N; uint64_t br=0;
        dprime.v[0]=subb64(N[0], dprime.v[0], br);
        dprime.v[1]=subb64(N[1], dprime.v[1], br);
        dprime.v[2]=subb64(N[2], dprime.v[2], br);
        dprime.v[3]=subb64(N[3], dprime.v[3], br);
    }
    // aux
    uint8_t aux[32]; if (aux32) std::memcpy(aux, aux32, 32); else std::memset(aux, 0, 32);
    uint8_t t32[32]; sha256_tagged("BIP0340/aux", aux, 32, t32);
    for (int i=0;i<32;i++) t32[i] ^= priv32[i];
    // k0 = int(sha256_tagged("BIP0340/nonce", t32 || px || m)) mod n
    uint8_t nonce_in[32+32+32]; std::memcpy(nonce_in, t32, 32); std::memcpy(nonce_in+32, px, 32); std::memcpy(nonce_in+64, msg32, 32);
    uint8_t k0hash[32]; sha256_tagged("BIP0340/nonce", nonce_in, 96, k0hash);
    U256 k0 = U256::from_be32(k0hash); if ((k0.v[0]|k0.v[1]|k0.v[2]|k0.v[3])==0ULL){ return false; } sign::Fn::mod_n(k0);
    if ((k0.v[0]|k0.v[1]|k0.v[2]|k0.v[3])==0ULL){ return false; }
    // R = k*G ; se y(R) ímpar, k = n - k, e r = x(R)
    ECPointA R = Secp256k1::to_affine(Secp256k1::scalar_mul(k0, Secp256k1::G()));
    uint8_t rx[32]; bool Ry_odd=false; xonly_from_point(R, rx, Ry_odd);
    U256 k = k0;
    if (Ry_odd){
        const uint64_t* N = sign::Fn::N; uint64_t br=0;
        k.v[0]=subb64(N[0], k.v[0], br);
        k.v[1]=subb64(N[1], k.v[1], br);
        k.v[2]=subb64(N[2], k.v[2], br);
        k.v[3]=subb64(N[3], k.v[3], br);
    }
    // e = int(sha256_tagged("BIP0340/challenge", r || px || m)) mod n
    uint8_t chal_in[32+32+32]; std::memcpy(chal_in, rx, 32); std::memcpy(chal_in+32, px, 32); std::memcpy(chal_in+64, msg32, 32);
    uint8_t ehash[32]; sha256_tagged("BIP0340/challenge", chal_in, 96, ehash);
    U256 e = U256::from_be32(ehash); sign::Fn::mod_n(e);
    // s = (k + e*d') mod n
    sign::Fn fk = sign::Fn::from_u256_nm(k);
    sign::Fn fe = sign::Fn::from_u256_nm(e);
    sign::Fn fd = sign::Fn::from_u256_nm(dprime);
    sign::Fn ed = sign::Fn::mul(fe, fd);
    sign::Fn sum = sign::Fn::add(fk, ed);
    U256 s = sum.to_u256_nm();
    // sig = r||s
    std::memcpy(sig64, rx, 32); s.to_be32(sig64+32);
    return true;
}

inline bool schnorr_verify_xonly(const uint8_t pubx32[32], const uint8_t msg32[32], const uint8_t sig64[64]){
    using namespace bitcrypto;
    using namespace bitcrypto::hash;
    // parse r,s
    U256 r = U256::from_be32(sig64);
    U256 s = U256::from_be32(sig64+32);
    if ((s.v[0]|s.v[1]|s.v[2]|s.v[3])==0ULL || sign::Fn::geq_n(s)) return false;
    // P: x-only com Y par (por definição na verificação)
    U256 px = U256::from_be32(pubx32);
    ECPointA P; P.x = Fp::from_u256_nm(px);
    // y^2 = x^3 + 7 ; Y = sqrt(...)
    Fp y2 = Fp::add(Fp::mul(Fp::mul(P.x,P.x), P.x), Secp256k1::b());
    Fp Y = Fp::sqrt(y2);
    // força Y par
    U256 ynm = Y.to_u256_nm(); if (ynm.v[0] & 1ULL){ Y = Fp::sub(Fp::zero(), Y); }
    P.y = Y; P.infinity=false;
    if (!Secp256k1::is_on_curve(P)) return false;

    // e = int(sha256_tagged("BIP0340/challenge", r || px || m)) mod n
    uint8_t rx[32]; r.to_be32(rx);
    uint8_t chal_in[32+32+32]; std::memcpy(chal_in, rx, 32); std::memcpy(chal_in+32, pubx32, 32); std::memcpy(chal_in+64, msg32, 32);
    uint8_t ehash[32]; sha256_tagged("BIP0340/challenge", chal_in, 96, ehash);
    U256 e = U256::from_be32(ehash); sign::Fn::mod_n(e);

    // R' = s*G - e*P = s*G + (n-e)*P
    const uint64_t* N = sign::Fn::N;
    U256 ne = e; uint64_t br=0;
    ne.v[0]=subb64(N[0], ne.v[0], br);
    ne.v[1]=subb64(N[1], ne.v[1], br);
    ne.v[2]=subb64(N[2], ne.v[2], br);
    ne.v[3]=subb64(N[3], ne.v[3], br);

    ECPointJ A = Secp256k1::scalar_mul(s, Secp256k1::G());
    ECPointJ B = Secp256k1::scalar_mul(ne, P);
    ECPointJ Rj = Secp256k1::add(A, B);
    if (Secp256k1::is_infinity(Rj)) return false;
    ECPointA R = Secp256k1::to_affine(Rj);
    // y(R) deve ser par
    bitcrypto::U256 Ry = R.y.to_u256_nm();
    if ( (Ry.v[0] & 1ULL) != 0ULL ) return false;
    U256 rcalc = R.x.to_u256_nm();
    // rcalc == r ?
    return (rcalc.v[0]==r.v[0] && rcalc.v[1]==r.v[1] && rcalc.v[2]==r.v[2] && rcalc.v[3]==r.v[3]);
}

inline bool schnorr_verify(const uint8_t* pub, size_t publen_or_32, const uint8_t msg32[32], const uint8_t sig64[64]){
    if (publen_or_32==32){
        return schnorr_verify_xonly(pub, msg32, sig64);
    } else {
        bitcrypto::ECPointA Q; if (!bitcrypto::parse_pubkey(pub, publen_or_32, Q)) return false;
        uint8_t px[32]; bool odd=false; xonly_from_point(Q, px, odd);
        // normalizar para Y par (se odd, use n-d para derivar o mesmo x-only; verif usa x-only de Y par)
        return schnorr_verify_xonly(px, msg32, sig64);
    }
}

}} // ns
