#include <cstring>
#include <vector>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/bip322.h>

namespace bitcrypto { namespace sign {

Signature sign_message(const U256& priv, std::string_view msg){
    // Deriva a chave pública comprimida a partir da chave privada
    auto Pub = Secp256k1::derive_pubkey(priv);
    uint8_t pub_ser[33]; size_t plen=0; encode_pubkey(Pub, true, pub_ser, plen);

    // Concatena pub||msg e aplica o hash "tagged" do BIP-322
    std::vector<uint8_t> buf(plen + msg.size());
    std::memcpy(buf.data(), pub_ser, plen);
    std::memcpy(buf.data() + plen, msg.data(), msg.size());

    Signature out{};
    uint8_t h1[32]; hash::sha256_tagged("BIP0322-signed-message", buf.data(), buf.size(), h1);
    uint8_t h2[32]; hash::sha256(h1, 32, h2);
    std::memcpy(out.r, h1, 32);
    std::memcpy(out.s, h2, 32);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;

    // Serializa a chave pública comprimida
    uint8_t pub_ser[33]; size_t plen=0; encode_pubkey(pub, true, pub_ser, plen);

    // Reproduz o hash determinístico pub||msg
    std::vector<uint8_t> buf(plen + msg.size());
    std::memcpy(buf.data(), pub_ser, plen);
    std::memcpy(buf.data() + plen, msg.data(), msg.size());

    uint8_t h1[32]; hash::sha256_tagged("BIP0322-signed-message", buf.data(), buf.size(), h1);
    uint8_t h2[32]; hash::sha256(h1, 32, h2);
    return std::memcmp(sig.r, h1, 32)==0 && std::memcmp(sig.s, h2, 32)==0;
}

}} // namespace bitcrypto::sign
