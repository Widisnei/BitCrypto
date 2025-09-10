#include <cstring>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/bip322.h>
#include <bitcrypto/field_n.h>
#include <bitcrypto/encoding/taproot.h>

namespace bitcrypto { namespace sign {

Signature sign_message(const U256& priv, std::string_view msg){
    Signature out{};
    U256 d = priv; Secp256k1::scalar_mod_n(d); if (d.is_zero()) return out;

    // Chave pública normalizada com y par
    auto P = Secp256k1::derive_pubkey(d);
    uint8_t px[32]; bool neg=false; auto Peven = encoding::normalize_even_y(P, px, neg);
    if (neg){
        const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
        uint64_t br=0; d.v[0]=subb64(N[0],d.v[0],br); d.v[1]=subb64(N[1],d.v[1],br);
        d.v[2]=subb64(N[2],d.v[2],br); d.v[3]=subb64(N[3],d.v[3],br);
    }

    // Hash da mensagem (BIP-322)
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), h);

    // Nonce determinístico BIP-340
    uint8_t t[32]; d.to_be32(t);
    uint8_t nonce_in[96];
    std::memcpy(nonce_in, t, 32);
    std::memcpy(nonce_in+32, px, 32);
    std::memcpy(nonce_in+64, h, 32);
    uint8_t kn[32];
    hash::sha256_tagged("BIP0340/nonce", nonce_in, sizeof(nonce_in), kn);
    U256 k = U256::from_be32(kn); Secp256k1::scalar_mod_n(k); if (k.is_zero()) return out;

    auto R = Secp256k1::to_affine(Secp256k1::scalar_mul(k, Secp256k1::G()));
    uint8_t rx[32]; bool Rneg=false; auto Re = encoding::normalize_even_y(R, rx, Rneg);
    if (Rneg){
        const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
        uint64_t br=0; k.v[0]=subb64(N[0],k.v[0],br); k.v[1]=subb64(N[1],k.v[1],br);
        k.v[2]=subb64(N[2],k.v[2],br); k.v[3]=subb64(N[3],k.v[3],br);
    }

    uint8_t chal[96];
    std::memcpy(chal, rx, 32);
    std::memcpy(chal+32, px, 32);
    std::memcpy(chal+64, h, 32);
    uint8_t eh[32];
    hash::sha256_tagged("BIP0340/challenge", chal, sizeof(chal), eh);
    U256 e = U256::from_be32(eh); Secp256k1::scalar_mod_n(e);

    Fn s_fn = Fn::add(Fn::from_u256_nm(k), Fn::mul(Fn::from_u256_nm(e), Fn::from_u256_nm(d)));
    U256 s = s_fn.to_u256_nm();
    std::memcpy(out.r, rx, 32); s.to_be32(out.s);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;
    U256 s = U256::from_be32(sig.s); Secp256k1::scalar_mod_n(s); if (s.is_zero()) return false;
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), h);

    uint8_t px[32]; bool neg=false; auto Peven = encoding::normalize_even_y(pub, px, neg);

    uint8_t chal[96];
    std::memcpy(chal, sig.r, 32);
    std::memcpy(chal+32, px, 32);
    std::memcpy(chal+64, h, 32);
    uint8_t eh[32];
    hash::sha256_tagged("BIP0340/challenge", chal, sizeof(chal), eh);
    U256 e = U256::from_be32(eh); Secp256k1::scalar_mod_n(e);

    ECPointJ R1 = Secp256k1::scalar_mul(s, Secp256k1::G());
    ECPointJ R2 = Secp256k1::scalar_mul(e, Peven);
    ECPointA R2a = Secp256k1::to_affine(R2); R2a.y = Fp::sub(Fp::zero(), R2a.y);
    ECPointJ Rj = Secp256k1::add(R1, Secp256k1::to_jacobian(R2a));
    if (Secp256k1::is_infinity(Rj)) return false;
    ECPointA Ra = Secp256k1::to_affine(Rj);
    uint8_t rx[32]; bool Rneg=false; auto Re = encoding::normalize_even_y(Ra, rx, Rneg); if (Rneg) return false;
    for (int i=0;i<32;i++) if (rx[i]!=sig.r[i]) return false;
    return true;
}

}} // namespace bitcrypto::sign
