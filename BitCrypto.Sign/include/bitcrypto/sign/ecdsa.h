#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/hmac.h>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/ec_parse.h>
#include "scalar_n.h"
#include "der.h"

namespace bitcrypto { namespace sign {

inline void u256_to_be32(const bitcrypto::U256& a, uint8_t out[32]){ a.to_be32(out); }
inline bitcrypto::U256 be32_to_u256(const uint8_t in[32]){ return bitcrypto::U256::from_be32(in); }

inline bool u256_is_zero(const bitcrypto::U256& a){ return (a.v[0]|a.v[1]|a.v[2]|a.v[3])==0ULL; }
inline bool u256_gt(const bitcrypto::U256& a, const bitcrypto::U256& b){
    if (a.v[3]!=b.v[3]) return a.v[3]>b.v[3];
    if (a.v[2]!=b.v[2]) return a.v[2]>b.v[2];
    if (a.v[1]!=b.v[1]) return a.v[1]>b.v[1];
    return a.v[0]>b.v[0];
}

// RFC6979 (SHA-256) – determinístico k em [1..n-1]
inline bool rfc6979_k(const uint8_t priv32[32], const uint8_t hash32[32], uint8_t k_out[32]){
    using namespace bitcrypto::hash;
    uint8_t x[32]; std::memcpy(x, priv32, 32);
    bitcrypto::U256 hz = bitcrypto::U256::from_be32(hash32); bitcrypto::sign::Fn::mod_n(hz); uint8_t h[32]; hz.to_be32(h);
    uint8_t V[32]; std::memset(V, 0x01, 32);
    uint8_t K[32]; std::memset(K, 0x00, 32);
    // K = HMAC(K, V||0x00||x||h)
    uint8_t buf[32+1+32+32];
    std::memcpy(buf, V, 32); buf[32]=0x00; std::memcpy(buf+33, x, 32); std::memcpy(buf+65, h, 32);
    hmac_sha256(K, 32, buf, 97, K);
    // V = HMAC(K, V)
    hmac_sha256(K, 32, V, 32, V);
    // K = HMAC(K, V||0x01||x||h)
    std::memcpy(buf, V, 32); buf[32]=0x01; std::memcpy(buf+33, x, 32); std::memcpy(buf+65, h, 32);
    hmac_sha256(K, 32, buf, 97, K);
    hmac_sha256(K, 32, V, 32, V);
    while (true){
        hmac_sha256(K, 32, V, 32, V);
        std::memcpy(k_out, V, 32);
        bitcrypto::U256 k = bitcrypto::U256::from_be32(k_out);
        if (!u256_is_zero(k)){
            bitcrypto::U256 kk = k; if (bitcrypto::sign::Fn::geq_n(kk)){ bitcrypto::sign::Fn::mod_n(kk); }
            if (!u256_is_zero(kk)){ kk.to_be32(k_out); return true; }
        }
        uint8_t data[33]; std::memcpy(data, V, 32); data[32]=0x00;
        hmac_sha256(K, 32, data, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }
}

// ECDSA: retorna DER estrito; aplica low-S
inline bool ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32], std::vector<uint8_t>& der_out){
    using namespace bitcrypto;
    U256 d = U256::from_be32(priv32); if (u256_is_zero(d) || sign::Fn::geq_n(d)) return false;
    uint8_t k32[32]; if (!rfc6979_k(priv32, hash32, k32)) return false;
    U256 k = U256::from_be32(k32); if (u256_is_zero(k)) return false;

    auto Rj = Secp256k1::scalar_mul(k, Secp256k1::G()); auto R = Secp256k1::to_affine(Rj);
    U256 rx = R.x.to_u256_nm(); sign::Fn::mod_n(rx); if (u256_is_zero(rx)) return false;

    U256 z = U256::from_be32(hash32); sign::Fn::mod_n(z);
    sign::Fn fr = sign::Fn::from_u256_nm(rx);
    sign::Fn fd = sign::Fn::from_u256_nm(d);
    sign::Fn fz = sign::Fn::from_u256_nm(z);
    sign::Fn frd = sign::Fn::mul(fr, fd);
    sign::Fn num = sign::Fn::add(fz, frd);
    sign::Fn fk = sign::Fn::from_u256_nm(k);
    sign::Fn kinv = sign::Fn::inv(fk);
    sign::Fn fs = sign::Fn::mul(kinv, num);
    U256 s = fs.to_u256_nm();

    // low-S
    U256 halfN{{0xDFE92F46681B20A0ULL,0x5D576E7357A4501DULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}};
    if (u256_gt(s, halfN)){
        const uint64_t* N = sign::Fn::N;
        uint64_t br=0;
        s.v[0]=subb64(N[0], s.v[0], br);
        s.v[1]=subb64(N[1], s.v[1], br);
        s.v[2]=subb64(N[2], s.v[2], br);
        s.v[3]=subb64(N[3], s.v[3], br);
    }

    uint8_t r32[32], s32[32]; rx.to_be32(r32); s.to_be32(s32);
    der_out = DER::encode_signature_rs(r32, s32);
    return true;
}

inline bool ecdsa_verify(const uint8_t* pubkey, size_t publen, const uint8_t hash32[32], const uint8_t* der, size_t der_len){
    using namespace bitcrypto;
    ECPointA Q; if (!parse_pubkey(pubkey, publen, Q)) return false;

    // decodifica DER
    uint8_t r32[32], s32[32]; if (!DER::decode_signature_rs(der, der_len, r32, s32)) return false;
    U256 r = U256::from_be32(r32), s = U256::from_be32(s32);
    if (u256_is_zero(r) || u256_is_zero(s) || sign::Fn::geq_n(r) || sign::Fn::geq_n(s)) return false;

    // w = s^{-1} mod n
    sign::Fn fs = sign::Fn::from_u256_nm(s);
    sign::Fn w = sign::Fn::inv(fs);
    // u1 = z*w ; u2 = r*w
    U256 z = U256::from_be32(hash32); sign::Fn::mod_n(z);
    sign::Fn fz = sign::Fn::from_u256_nm(z);
    sign::Fn fr = sign::Fn::from_u256_nm(r);
    sign::Fn fu1 = sign::Fn::mul(fz, w);
    sign::Fn fu2 = sign::Fn::mul(fr, w);
    U256 u1 = fu1.to_u256_nm();
    U256 u2 = fu2.to_u256_nm();

    // X = u1*G + u2*Q
    ECPointJ X1 = Secp256k1::scalar_mul(u1, Secp256k1::G());
    ECPointJ X2 = Secp256k1::scalar_mul(u2, Q);
    ECPointJ X = Secp256k1::add(X1, X2);
    if (Secp256k1::is_infinity(X)) return false;
    ECPointA Xa = Secp256k1::to_affine(X);
    U256 vx = Xa.x.to_u256_nm(); sign::Fn::mod_n(vx);
    // v == r ?
    return (vx.v[0]==r.v[0] && vx.v[1]==r.v[1] && vx.v[2]==r.v[2] && vx.v[3]==r.v[3]);
}

}} // ns
