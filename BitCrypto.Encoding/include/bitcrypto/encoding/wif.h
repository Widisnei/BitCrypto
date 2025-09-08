#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "base58.h"
#include "b58check.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/hash160.h"
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
namespace bitcrypto { namespace encoding {
enum class Network: uint8_t { MAINNET=0, TESTNET=1 };
struct AddressResult{ std::string pubkey_hex; std::string address_base58; };
inline std::string to_hex(const uint8_t* p,size_t n){ static const char* hx="0123456789abcdef"; std::string s; s.resize(n*2); for(size_t i=0;i<n;i++){ s[2*i]=hx[(p[i]>>4)&0xF]; s[2*i+1]=hx[p[i]&0xF]; } return s; }
inline std::string to_wif(const uint8_t priv32[32], bool compressed, Network net=Network::MAINNET){
    uint8_t prefix = (net==Network::MAINNET)?0x80:0xEF; std::vector<uint8_t> payload; payload.push_back(prefix); payload.insert(payload.end(), priv32, priv32+32); if (compressed) payload.push_back(0x01); return base58check_encode(payload);
}
inline bool from_wif(const std::string& wif, uint8_t out_priv32[32], bool& compressed, Network& net){
    std::vector<uint8_t> payload;
    if (!base58check_decode(wif, payload)) return false;
    if (payload.size()!=33 && payload.size()!=34) return false;
    uint8_t prefix = payload[0];
    if (prefix==0x80) net = Network::MAINNET;
    else if (prefix==0xEF) net = Network::TESTNET;
    else return false;
    if (payload.size()==34){
        if (payload.back()!=0x01) return false;
        compressed = true;
    } else {
        compressed = false;
    }
    std::copy(payload.begin()+1, payload.begin()+33, out_priv32);
    return true;
}
inline AddressResult p2pkh_from_priv(const uint8_t priv32_be[32], bool compressed, Network net=Network::MAINNET){
    using namespace bitcrypto; using namespace bitcrypto::hash; U256 k=U256::from_be32(priv32_be); auto Pub=Secp256k1::derive_pubkey(k);
    uint8_t pub[65]; size_t plen=0; encode_pubkey(Pub, compressed, pub, plen); uint8_t h160[20]; hash160(pub, plen, h160);
    uint8_t ver=(net==Network::MAINNET)?0x00:0x6F; std::vector<uint8_t> payload; payload.push_back(ver); payload.insert(payload.end(), h160, h160+20);
    AddressResult r; r.pubkey_hex = to_hex(pub,plen); r.address_base58 = base58check_encode(payload); return r;
}
inline bool p2pkh_decode_address(const std::string& addr, uint8_t& version, uint8_t out_h160[20]){
    std::vector<uint8_t> payload; if (!base58check_decode(addr, payload) || payload.size()!=21) return false; version=payload[0]; for(int i=0;i<20;i++) out_h160[i]=payload[1+i]; return true;
}
}}