#include <cstring>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/bip322.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/encoding/taproot.h>

namespace bitcrypto { namespace sign {

Signature sign_message(const U256& priv, std::string_view msg){
    Signature out{};
    uint8_t priv32[32]; priv.to_be32(priv32);
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), h);
    uint8_t sig64[64];
    if (!schnorr_sign_bip340(priv32, h, sig64)) return out;
    std::memcpy(out.r, sig64, 32);
    std::memcpy(out.s, sig64+32, 32);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), h);
    uint8_t px[32]; bool neg=false; encoding::normalize_even_y(pub, px, neg);
    uint8_t sig64[64]; std::memcpy(sig64, sig.r, 32); std::memcpy(sig64+32, sig.s, 32);
    return schnorr_verify_bip340(px, h, sig64);
}

}} // namespace bitcrypto::sign
