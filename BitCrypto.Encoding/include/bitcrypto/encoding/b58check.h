#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include "../../BitCrypto.Hash/include/bitcrypto/hash/sha256.h"
#include "base58.h"
namespace bitcrypto { namespace encoding {

inline std::string base58check_encode(const std::vector<uint8_t>& payload){
    using namespace bitcrypto::hash;
    uint8_t d1[32], d2[32];
    sha256(payload.data(), payload.size(), d1);
    sha256(d1, 32, d2);
    std::vector<uint8_t> full = payload;
    full.insert(full.end(), d2, d2+4);
    return base58_encode(full.data(), full.size());
}

inline bool base58check_decode(const std::string& s, std::vector<uint8_t>& payload_out){
    std::vector<uint8_t> full;
    if (!base58_decode(s, full) || full.size()<4) return false;
    size_t ps = full.size() - 4;
    using namespace bitcrypto::hash;
    uint8_t d1[32], d2[32];
    sha256(full.data(), ps, d1);
    sha256(d1, 32, d2);
    if (std::memcmp(d2, full.data()+ps, 4)!=0) return false;
    payload_out.assign(full.begin(), full.begin()+ps);
    return true;
}

}} // ns
