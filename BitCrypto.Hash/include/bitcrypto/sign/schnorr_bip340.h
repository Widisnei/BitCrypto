#pragma once
// Assinatura Schnorr (BIP-340) para secp256k1 (sem script path).
// Usa sha256_tagged e aritmética mod n (Sn).

#include <cstdint>
#include <cstddef>
#include <array>
#include <string.h>
#include "../hash/sha256.h"
#include "../hash/tagged_hash.h"
#include "../../BitCrypto.Core/include/bitcrypto/u256.h"
#include "../../BitCrypto.Core/include/bitcrypto/scalar_n.h"
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"

namespace bitcrypto { namespace sign {

// Constrói x-only e garante Y par (se Y ímpar, nega ponto e ajusta d).
BITCRYPTO_HD inline void xonly_even(const bitcrypto::ECPointA& P_in, uint8_t x32[32], bool& negated){
    using namespace bitcrypto;
    U256 y = P_in.y.to_u256_nm();
    bool odd = (y.v[0] & 1ULL) != 0ULL;
    ECPointA P = P_in;
    if (odd){ P.y = Fp::sub(Fp::zero(), P.y); negated=true; } else { negated=false; }
    U256 x = P.x.to_u256_nm(); x.to_be32(x32);
}

// Assina: msg32 = SHA256(mensagem). Se quiser usar msg direto, hasheie antes.
// aux32 pode ser nulo (usa zeros).
inline bool schnorr_sign(const uint8_t priv32[32], const uint8_t msg32[32], uint8_t sig64[64], const uint8_t aux32_in[32]=nullptr){
    using namespace bitcrypto;
    using namespace bitcrypto::hash;

    // 1) chave pública P e normalização para Y par
    U256 d = U256::from_be32(priv32); Secp256k1::scalar_mod_n(d);
    if (d.is_zero()) return false;
    auto P = Secp256k1::derive_pubkey(d);
    uint8_t px[32]; bool neg=false;
    sign::xonly_even(P, px, neg);
    // Se Y era ímpar, usa d = n - d
    if (neg){
        const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
        uint64_t br=0;
        d.v[0]=subb64(N[0], d.v[0], br);
        d.v[1]=subb64(N[1], d.v[1], br);
        d.v[2]=subb64(N[2], d.v[2], br);
        d.v[3]=subb64(N[3], d.v[3], br);
    }

    // 2) aux (BIP-340/aux): t = d XOR sha256_tagged("BIP0340/aux", aux32)
    uint8_t aux32[32]={0}; if (aux32_in) memcpy(aux32, aux32_in, 32);
    uint8_t ta[32]; sha256_tagged("BIP0340/aux", aux32, 32, ta);
    uint8_t be[32]; d.to_be32(be);
    uint8_t t[32]; for(int i=0;i<32;i++){ t[i]=(uint8_t)(be[i]^ta[i]); }

    // 3) k0 = int(sha256_tagged("BIP0340/nonce", t || px || msg32)) mod n; se zero → falha
    uint8_t buf[32+32+32];
    memcpy(buf, t, 32); memcpy(buf+32, px, 32); memcpy(buf+64, msg32, 32);
    uint8_t kn[32]; sha256_tagged("BIP0340/nonce", buf, sizeof(buf), kn);
    U256 k = U256::from_be32(kn); Secp256k1::scalar_mod_n(k);
    if (k.is_zero()) return false;

    // 4) R = k*G; se Y(R) ímpar, k = n - k; r = x(R)
    auto Rj = Secp256k1::scalar_mul(k, Secp256k1::G());
    auto R = Secp256k1::to_affine(Rj);
    uint8_t rx[32]; bool r_odd=false; sign::xonly_even(R, rx, r_odd);
    if (r_odd){
        const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
        uint64_t br=0;
        k.v[0]=subb64(N[0], k.v[0], br);
        k.v[1]=subb64(N[1], k.v[1], br);
        k.v[2]=subb64(N[2], k.v[2], br);
        k.v[3]=subb64(N[3], k.v[3], br);
    }

    // 5) e = int(sha256_tagged("BIP0340/challenge", rx || px || msg32)) mod n
    uint8_t ce[32+32+32];
    memcpy(ce, rx, 32); memcpy(ce+32, px, 32); memcpy(ce+64, msg32, 32);
    uint8_t eh[32]; sha256_tagged("BIP0340/challenge", ce, sizeof(ce), eh);
    U256 e = U256::from_be32(eh); Secp256k1::scalar_mod_n(e);

    // s = (k + e*d) mod n  (via Montgomery Sn)
    Sn km = Sn::from_u256_nm(k);
    Sn em = Sn::from_u256_nm(e);
    Sn dm = Sn::from_u256_nm(d);
    Sn s = Sn::add(km, Sn::mul(em, dm));
    U256 s_u = s.to_u256_nm();

    // Assinatura = rx (32) || s (32)
    uint8_t su_be[32]; s_u.to_be32(su_be);
    memcpy(sig64, rx, 32); memcpy(sig64+32, su_be, 32);
    return true;
}

// Verifica assinatura BIP-340
inline bool schnorr_verify(const uint8_t pubkey_xonly[32], const uint8_t msg32[32], const uint8_t sig64[64]){
    using namespace bitcrypto;
    using namespace bitcrypto::hash;

    U256 r = U256::from_be32(sig64);
    U256 s = U256::from_be32(sig64+32);

    const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    // Rejeita s>=n
    uint64_t br=0; (void)subb64(s.v[0],N[0],br); (void)subb64(s.v[1],N[1],br); (void)subb64(s.v[2],N[2],br); (void)subb64(s.v[3],N[3],br);
    if (br==0) return false;

    // Reconstrói P a partir de x (y par)
    using Fp = bitcrypto::Fp;
    U256 xu = U256::from_be32(pubkey_xonly);
    Fp x = Fp::from_u256_nm(xu);
    Fp rhs = Fp::add(Fp::mul(Fp::sqr(x), x), Secp256k1::b());
    // y = rhs^((p+1)/4)
    U256 e{{0xFFFFFFFFFFFFFC30ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x3FFFFFFFFFFFFFFFULL}};
    Fp y = Fp::pow(rhs, e);
    // y par
    U256 y_nm = y.to_u256_nm();
    if (y_nm.v[0] & 1ULL){ y = Fp::sub(Fp::zero(), y); }
    ECPointA P{ x, y, false };

    // e = H(challenge, r||px||m) mod n
    uint8_t ce[32+32+32]; memcpy(ce, sig64, 32); memcpy(ce+32, pubkey_xonly, 32); memcpy(ce+64, msg32, 32);
    uint8_t eh[32]; sha256_tagged("BIP0340/challenge", ce, sizeof(ce), eh);
    U256 e = U256::from_be32(eh); Secp256k1::scalar_mod_n(e);

    ECPointJ sG = Secp256k1::scalar_mul(s, Secp256k1::G());
    ECPointJ eP = Secp256k1::scalar_mul(e, P);
    eP.Y = Fp::sub(Fp::zero(), eP.Y);
    ECPointJ Rj = Secp256k1::add(sG, eP);
    if (Secp256k1::is_infinity(Rj)) return false;
    auto R = Secp256k1::to_affine(Rj);
    U256 rx = R.x.to_u256_nm();
    U256 ry = R.y.to_u256_nm();
    if ( (ry.v[0] & 1ULL) != 0ULL ) return false;
    for (int i=0;i<4;i++) if (rx.v[i]!=r.v[i]) return false;
    return true;
}

}} // ns
