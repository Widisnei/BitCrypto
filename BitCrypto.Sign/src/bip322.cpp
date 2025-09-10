#include <cstring>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/sign/bip322.h>

namespace bitcrypto { namespace sign {

Signature sign_message(const U256& priv, std::string_view msg){
    Signature out{};
    uint8_t priv32[32]; priv.to_be32(priv32);
    uint8_t h[32];
    // Hash taggeado "BIP0322-signed-message"
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), h);
    uint8_t sig64[64];
    // Assina via Schnorr BIP-340
    if (!schnorr_sign_bip340(priv32, h, sig64)) return out;
    std::memcpy(out.r, sig64, 32);
    std::memcpy(out.s, sig64+32, 32);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;
    uint8_t h[32];
    // Recalcula o hash taggeado da mensagem
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), h);
    uint8_t xonly[32];
    auto x = pub.x.to_u256_nm(); x.to_be32(xonly);
    uint8_t sig64[64];
    std::memcpy(sig64, sig.r, 32);
    std::memcpy(sig64+32, sig.s, 32);
    // Verifica assinatura Schnorr BIP-340
    return schnorr_verify_bip340(xonly, h, sig64);
}

}} // namespace bitcrypto::sign
