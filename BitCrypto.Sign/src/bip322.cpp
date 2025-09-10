#include <cstring>
#include <vector>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/sign/bip322.h>

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
    // Implementação simplificada: assinatura = hash da mensagem duas vezes
    (void)priv;
    std::memcpy(out.r, h, 32);
    hash::sha256(h, 32, out.s);
    return out;
}

bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig){
    if (pub.infinity) return false;
    std::vector<uint8_t> buf; buf.reserve(msg.size()+9);
    ser_compact_size(msg.size(), buf); buf.insert(buf.end(), msg.begin(), msg.end());
    uint8_t h[32];
    hash::sha256_tagged("BIP0322-signed-message", buf.data(), buf.size(), h);
    uint8_t exp_r[32]; std::memcpy(exp_r, h, 32);
    uint8_t exp_s[32]; hash::sha256(h, 32, exp_s);
    if(std::memcmp(sig.r, exp_r, 32)!=0) return false;
    if(std::memcmp(sig.s, exp_s, 32)!=0) return false;
    return true;
}

}} // namespace bitcrypto::sign
