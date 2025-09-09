#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <bitcrypto/hash/tagged_hash.h>

namespace bitcrypto { namespace tx {

static inline void ser_compact_size(std::vector<uint8_t>& out, uint64_t v){
    if (v < 253){ out.push_back((uint8_t)v); return; }
    if (v <= 0xFFFF){ out.push_back(253); out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v>>8)&0xFF)); return; }
    if (v <= 0xFFFFFFFFULL){ out.push_back(254); for (int i=0;i<4;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF)); return; }
    out.push_back(255); for (int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF));
}

// BIP342 TapLeaf hash: H_TapLeaf(leaf_ver || varint(len(script)) || script)
static inline void tapleaf_hash(const std::vector<uint8_t>& script, uint8_t leaf_ver, uint8_t out32[32]){
    std::vector<uint8_t> data; data.reserve(1 + 9 + script.size());
    data.push_back(leaf_ver);
    ser_compact_size(data, (uint64_t)script.size());
    data.insert(data.end(), script.begin(), script.end());
    bitcrypto::hash::sha256_tagged("TapLeaf", data.data(), data.size(), out32);
}

}} // ns
