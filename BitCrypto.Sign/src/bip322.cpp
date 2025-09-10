#include <cstring>
#include <vector>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/bip322.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/encoding/taproot.h>

namespace bitcrypto { namespace sign {

// Serializa CompactSize (varint)
static void ser_compact_size(uint64_t v, std::vector<uint8_t>& out){
    if (v < 0xFD){ out.push_back((uint8_t)v); return; }
    if (v <= 0xFFFF){ out.push_back(0xFD); out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)(v >> 8)); return; }
    if (v <= 0xFFFFFFFFULL){ out.push_back(0xFE); for(int i=0;i<4;i++) out.push_back((uint8_t)(v >> (8*i))); return; }
    out.push_back(0xFF); for(int i=0;i<8;i++) out.push_back((uint8_t)(v >> (8*i)));
}

Signature sign_message(const U256& priv, std::string_view msg){
    Signature out{};
    std::vector<uint8_t> buf; buf.reserve(msg.size()+9);
    ser_compact_size(msg.size(), buf); buf.insert(buf.end(), msg.begin(), msg.end());
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", buf.data(), buf.size(), h);
    uint8_t priv32[32]; priv.to_be32(priv32);
    uint8_t sig64[64];
    uint8_t aux[32] = {0};
    if (!schnorr_sign_bip340(priv32, h, sig64, aux)) return out;
    std::memcpy(out.r, sig64, 32);
    std::memcpy(out.s, sig64+32, 32);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;
    std::vector<uint8_t> buf; buf.reserve(msg.size()+9);
    ser_compact_size(msg.size(), buf); buf.insert(buf.end(), msg.begin(), msg.end());
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", buf.data(), buf.size(), h);
    uint8_t px[32]; bool neg=false; encoding::normalize_even_y(pub, px, neg);
    if (neg) return false;
    uint8_t sig64[64]; std::memcpy(sig64, sig.r, 32); std::memcpy(sig64+32, sig.s, 32);
    return schnorr_verify_bip340(px, h, sig64);
}

}} // namespace bitcrypto::sign
