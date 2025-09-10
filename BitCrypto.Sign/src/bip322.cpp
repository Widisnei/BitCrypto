#include <cstring>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/bip322.h>
#include <bitcrypto/sign/sign.h>

namespace bitcrypto { namespace sign {

Signature sign_message(const U256& priv, std::string_view msg){
    // Aplica o hash "tagged" do BIP-322 diretamente sobre a mensagem
    Signature out{}; uint8_t m[32];
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), m);

    // Assina via ECDSA determinístico (RFC6979)
    uint8_t priv32[32]; priv.to_be32(priv32);
    ECDSA_Signature ecd{};
    if (!ecdsa_sign_rfc6979(priv32, m, ecd)) return out;
    std::memcpy(out.r, ecd.r, 32); std::memcpy(out.s, ecd.s, 32);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;
    // Recalcula o hash "tagged" diretamente sobre a mensagem
    uint8_t m[32];
    hash::sha256_tagged("BIP0322-signed-message", (const uint8_t*)msg.data(), msg.size(), m);

    // Codifica a chave pública e verifica assinatura ECDSA
    uint8_t pub_ser[65]; size_t plen=0; encode_pubkey(pub, false, pub_ser, plen);
    ECDSA_Signature ecd{}; std::memcpy(ecd.r, sig.r, 32); std::memcpy(ecd.s, sig.s, 32);
    return ecdsa_verify(pub_ser, plen, m, ecd, true);
}

}} // namespace bitcrypto::sign
