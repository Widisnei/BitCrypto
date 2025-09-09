#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "bech32.h"
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/ec_secp256k1.h>
namespace bitcrypto { namespace encoding {
inline std::string segwit_hrp(bool testnet){ return testnet ? std::string("tb") : std::string("bc"); }
inline std::string p2wpkh_from_priv(const uint8_t priv32_be[32], bool compressed, bool testnet){
    using namespace bitcrypto; using namespace bitcrypto::hash;
    U256 k = U256::from_be32(priv32_be); auto Pub = Secp256k1::derive_pubkey(k);
    uint8_t pub[65]; size_t plen=0; encode_pubkey(Pub, compressed, pub, plen); uint8_t h160[20]; hash160(pub, plen, h160);
    std::vector<uint8_t> prog(h160, h160+20); std::vector<uint8_t> prog5; convert_bits(prog5, 5, prog, 8, true);
    std::vector<uint8_t> data; data.push_back(0); data.insert(data.end(), prog5.begin(), prog5.end());
    return bech32_encode(segwit_hrp(testnet), data, /*bech32m=*/false);
}
inline bool segwit_decode_address(const std::string& addr, std::string& hrp, int& version, std::vector<uint8_t>& program){
    std::vector<uint8_t> data; bool is_m=false; if(!bech32_decode(addr, hrp, data, is_m)) return false;
    if (data.size()<1) return false; version = (int)data[0]; if (version<0 || version>16) return false; if ((version==0 && is_m) || (version>=1 && !is_m)) return false;
    std::vector<uint8_t> data_nover(data.begin()+1, data.end()); program.clear(); if(!convert_bits(program, 8, data_nover, 5, false)) return false;
    if (program.size()<2 || program.size()>40) return false; if (version==0 && !(program.size()==20 || program.size()==32)) return false; return true;
}
inline bool p2wpkh_decode_address(const std::string& addr, bool& is_testnet, uint8_t out20[20]){
    std::string hrp; int ver=0; std::vector<uint8_t> prog; if(!segwit_decode_address(addr, hrp, ver, prog)) return false; if (ver!=0 || prog.size()!=20) return false;
    is_testnet = (hrp=="tb"); for(int i=0;i<20;i++) out20[i]=prog[i]; return true;
}
}}