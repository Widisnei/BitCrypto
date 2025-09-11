#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/field_n.h>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/hmac.h>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/encoding/der.h>
#include <bitcrypto/encoding/taproot.h>
#include <bitcrypto/utils/safe.h>

namespace bitcrypto { namespace sign {
inline void reduce_mod_n(U256& a){ Secp256k1::scalar_mod_n(a); }
inline bool is_zero32(const uint8_t x[32]){ uint8_t acc=0; for(int i=0;i<32;i++) acc|=x[i]; return acc==0; }

inline void rfc6979_nonce(const uint8_t priv32[32], const uint8_t hash32[32], uint8_t out_k[32]){
    using namespace bitcrypto::hash;
    uint8_t V[32]; std::memset(V, 0x01, 32);
    uint8_t K[32]; std::memset(K, 0x00, 32);
    uint8_t bx[32+1+32];
    std::memcpy(bx, priv32, 32); bx[32]=0x00; std::memcpy(bx+33, hash32, 32);
    hmac_sha256(K, 32, V, 32, K);
    hmac_sha256(K, 32, bx, 33+32, K);
    hmac_sha256(K, 32, V, 32, V);
    uint8_t tmp[32+1+33+32];
    std::memcpy(tmp, V, 32); tmp[32]=0x01; std::memcpy(tmp+33, bx, 33+32);
    hmac_sha256(K, 32, tmp, 33+33+32, K);
    hmac_sha256(K, 32, V, 32, V);
    uint8_t sep[1+33+32];
    while (true){
        hmac_sha256(K, 32, V, 32, V);
        std::memcpy(out_k, V, 32);
        U256 k = U256::from_be32(out_k);
        if (!k.is_zero()){
            U256 t=k;
            Secp256k1::scalar_mod_n(t);
            if (!t.is_zero()) break;
        }
        sep[0]=0x00; std::memcpy(sep+1, bx, 33+32);
        hmac_sha256(K, 32, V, 32, K);
        hmac_sha256(K, 32, sep, sizeof(sep), K);
        hmac_sha256(K, 32, V, 32, V);
    }
    secure_memzero(V, sizeof(V));
    secure_memzero(K, sizeof(K));
    secure_memzero(bx, sizeof(bx));
    secure_memzero(tmp, sizeof(tmp));
    secure_memzero(sep, sizeof(sep));
}

struct ECDSA_Signature { uint8_t r[32]; uint8_t s[32]; };

inline bool ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32], ECDSA_Signature& sig, bool low_s=true){
    using namespace bitcrypto;
    U256 d = U256::from_be32(priv32); Secp256k1::scalar_mod_n(d); if (d.is_zero()) return false;
    U256 e = U256::from_be32(hash32); reduce_mod_n(e);
    uint8_t k32[32]; rfc6979_nonce(priv32, hash32, k32);
    U256 k = U256::from_be32(k32);
    Secp256k1::scalar_mod_n(k);
    secure_memzero(k32, sizeof(k32));
    if (k.is_zero()) return false;
    ECPointJ Rj = Secp256k1::scalar_mul(k, Secp256k1::G());
    ECPointA Ra = Secp256k1::to_affine(Rj);
    U256 rx = Ra.x.to_u256_nm(); reduce_mod_n(rx); if (rx.is_zero()) return false; rx.to_be32(sig.r);
    Fn kinv = Fn::inv(Fn::from_u256_nm(k));
    Fn s_m = Fn::mul(kinv, Fn::add(Fn::from_u256_nm(e), Fn::mul(Fn::from_u256_nm(rx), Fn::from_u256_nm(d))));
    U256 s = s_m.to_u256_nm();
    if (low_s){
        const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
        uint64_t halfN[4] = {N[0]>>1 | (N[1]&1?0x8000000000000000ULL:0), (N[1]>>1) | (N[2]&1?0x8000000000000000ULL:0), (N[2]>>1) | (N[3]&1?0x8000000000000000ULL:0), (N[3]>>1)};
        bool gt=false; for (int i=3;i>=0;i--){ if (s.v[i]>halfN[i]) { gt=true; break; } else if (s.v[i]<halfN[i]) break; } if (gt){ uint64_t br=0; s.v[0]=subb64(N[0],s.v[0],br); s.v[1]=subb64(N[1],s.v[1],br); s.v[2]=subb64(N[2],s.v[2],br); s.v[3]=subb64(N[3],s.v[3],br); }
    }
    s.to_be32(sig.s);
    return !is_zero32(sig.s);
}

// Alias de compatibilidade com a nomenclatura anterior
inline bool ecdsa_sign_rfc6979(const uint8_t priv32[32], const uint8_t hash32[32], ECDSA_Signature& sig){
    return ecdsa_sign(priv32, hash32, sig, true);
}

inline bool ecdsa_verify(const uint8_t pubkey[], size_t publen, const uint8_t hash32[32], const ECDSA_Signature& sig, bool require_low_s=true){
    using namespace bitcrypto;
    if (!(publen==33 || publen==65)) return false;
    uint8_t prefix = pubkey[0];
    if (prefix==0x04 && publen==65){
        U256 x = U256::from_be32(pubkey+1), y = U256::from_be32(pubkey+33);
        ECPointA Q{Fp::from_u256_nm(x), Fp::from_u256_nm(y), false};
        Fp y2 = Fp::sqr(Q.y); Fp rhs = Fp::add(Fp::mul(Fp::sqr(Q.x), Q.x), Secp256k1::b());
        bool ok = (y2.v[0]==rhs.v[0] && y2.v[1]==rhs.v[1] && y2.v[2]==rhs.v[2] && y2.v[3]==rhs.v[3]); if (!ok) return false;
        U256 r = U256::from_be32(sig.r), s = U256::from_be32(sig.s); if (r.is_zero() || s.is_zero()) return false;
        if (require_low_s){
            const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
            uint64_t halfN[4] = {N[0]>>1 | (N[1]&1?0x8000000000000000ULL:0), (N[1]>>1) | (N[2]&1?0x8000000000000000ULL:0), (N[2]>>1) | (N[3]&1?0x8000000000000000ULL:0), (N[3]>>1)};
            for (int i=3;i>=0;i--){ if (s.v[i]>halfN[i]) return false; else if (s.v[i]<halfN[i]) break; }
        }
        U256 e = U256::from_be32(hash32); reduce_mod_n(e);
        Fn w = Fn::inv(Fn::from_u256_nm(s));
        Fn u1 = Fn::mul(Fn::from_u256_nm(e), w);
        Fn u2 = Fn::mul(Fn::from_u256_nm(r), w);
        U256 u1n=u1.to_u256_nm(), u2n=u2.to_u256_nm();
        ECPointJ R1 = Secp256k1::scalar_mul(u1n, Secp256k1::G());
        ECPointJ R2 = Secp256k1::scalar_mul(u2n, Q);
        ECPointJ Pj = Secp256k1::add(R1, R2);
        if (Secp256k1::is_infinity(Pj)) return false;
        ECPointA Pa = Secp256k1::to_affine(Pj);
        U256 xnorm = Pa.x.to_u256_nm(); reduce_mod_n(xnorm);
        uint8_t xr[32]; xnorm.to_be32(xr);
        for (int i=0;i<32;i++) if (xr[i]!=sig.r[i]) return false;
        return true;
    } else if ((prefix==0x02 || prefix==0x03) && publen==33){
        U256 x = U256::from_be32(pubkey+1);
        ECPointA Q; if (!Secp256k1::lift_x_even_y(x, Q)) return false;
        U256 y_nm = Q.y.to_u256_nm(); bool odd = (y_nm.v[0]&1ULL)!=0ULL; if ((prefix==0x03) != odd){ Q.y = Fp::sub(Fp::zero(), Q.y); }
        uint8_t unc[65]; size_t olen=0; encode_pubkey(Q, false, unc, olen);
        return ecdsa_verify(unc, olen, hash32, sig, require_low_s);
    } else return false;
}

inline std::vector<uint8_t> der_from_rs(const uint8_t r[32], const uint8_t s[32]){
    std::vector<uint8_t> out; bitcrypto::encoding::ecdsa_der_encode(r, s, out); return out;
}
inline bool der_to_rs(const std::vector<uint8_t>& der, uint8_t r[32], uint8_t s[32]){
    return bitcrypto::encoding::ecdsa_der_decode(der.data(), der.size(), r, s);
}

struct Schnorr_Signature { uint8_t r[32]; uint8_t s[32]; };
inline void xor32(uint8_t* a, const uint8_t* b){ for (int i=0;i<32;i++) a[i]^=b[i]; }

inline bool schnorr_sign_bip340(const uint8_t priv32[32], const uint8_t msg32[32], uint8_t out64[64], const uint8_t aux_rand32[32]=nullptr){
    using namespace bitcrypto;
    U256 d0 = U256::from_be32(priv32); Secp256k1::scalar_mod_n(d0); if (d0.is_zero()) return false;
    ECPointA P = Secp256k1::to_affine(Secp256k1::scalar_mul(d0, Secp256k1::G()));
    uint8_t px[32]; bool neg=false; encoding::normalize_even_y(P, px, neg);
    U256 d = d0; if (neg){ const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL}; uint64_t br=0; d.v[0]=subb64(N[0],d.v[0],br); d.v[1]=subb64(N[1],d.v[1],br); d.v[2]=subb64(N[2],d.v[2],br); d.v[3]=subb64(N[3],d.v[3],br); if (d.is_zero()) return false; }
    uint8_t t[32]; d.to_be32(t); if (aux_rand32){ uint8_t ah[32]; hash::sha256_tagged("BIP0340/aux", aux_rand32, 32, ah); xor32(t, ah); }
    uint8_t nonce_in[96]; std::memcpy(nonce_in, t, 32); std::memcpy(nonce_in+32, px, 32); std::memcpy(nonce_in+64, msg32, 32);
    uint8_t kn[32]; hash::sha256_tagged("BIP0340/nonce", nonce_in, sizeof(nonce_in), kn);
    U256 k0 = U256::from_be32(kn); Secp256k1::scalar_mod_n(k0); if (k0.is_zero()) return false;
    ECPointA R = Secp256k1::to_affine(Secp256k1::scalar_mul(k0, Secp256k1::G()));
    uint8_t rx[32]; bool Rneg=false; encoding::normalize_even_y(R, rx, Rneg);
    U256 k = k0; if (Rneg){ const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL}; uint64_t br=0; k.v[0]=subb64(N[0],k.v[0],br); k.v[1]=subb64(N[1],k.v[1],br); k.v[2]=subb64(N[2],k.v[2],br); k.v[3]=subb64(N[3],k.v[3],br); }
    uint8_t chal[96]; std::memcpy(chal, rx, 32); std::memcpy(chal+32, px, 32); std::memcpy(chal+64, msg32, 32);
    uint8_t eh[32]; hash::sha256_tagged("BIP0340/challenge", chal, sizeof(chal), eh);
    U256 e = U256::from_be32(eh); Secp256k1::scalar_mod_n(e);
    Fn s_m = Fn::add(Fn::from_u256_nm(k), Fn::mul(Fn::from_u256_nm(e), Fn::from_u256_nm(d)));
    U256 s = s_m.to_u256_nm();
    std::memcpy(out64, rx, 32); s.to_be32(out64+32); return true;
}

inline bool schnorr_verify_bip340(const uint8_t pubx32[32], const uint8_t msg32[32], const uint8_t sig64[64]){
    using namespace bitcrypto;
    U256 r = U256::from_be32(sig64); U256 s = U256::from_be32(sig64+32); Secp256k1::scalar_mod_n(s); if (s.is_zero()) return false;
    ECPointA P; U256 px = U256::from_be32(pubx32); if (!Secp256k1::lift_x_even_y(px, P)) return false;
    uint8_t rpxm[96]; uint8_t r_bytes[32]; r.to_be32(r_bytes); std::memcpy(rpxm, r_bytes, 32); std::memcpy(rpxm+32, pubx32, 32); std::memcpy(rpxm+64, msg32, 32);
    uint8_t eh[32]; hash::sha256_tagged("BIP0340/challenge", rpxm, sizeof(rpxm), eh);
    U256 e = U256::from_be32(eh); Secp256k1::scalar_mod_n(e);
    ECPointJ R1 = Secp256k1::scalar_mul(s, Secp256k1::G());
    ECPointJ R2 = Secp256k1::scalar_mul(e, P);
    ECPointA R2a = Secp256k1::to_affine(R2); R2a.y = Fp::sub(Fp::zero(), R2a.y);
    ECPointJ Rj = Secp256k1::add(R1, Secp256k1::to_jacobian(R2a));
    if (Secp256k1::is_infinity(Rj)) return false;
    ECPointA Ra = Secp256k1::to_affine(Rj);
    uint8_t rx[32]; bool neg=false; encoding::normalize_even_y(Ra, rx, neg); if (neg) return false;
    uint8_t r_bytes2[32]; r.to_be32(r_bytes2); for (int i=0;i<32;i++) if (rx[i]!=r_bytes2[i]) return false; return true;
}

// Aliases de compatibilidade com versões anteriores ------------------------
}}
