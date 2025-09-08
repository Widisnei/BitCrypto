#pragma once
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include "tapscript.h"

namespace bitcrypto { namespace tx {

static inline void tagged_hash_branch(const std::string& tag, const uint8_t* data, size_t len, uint8_t out32[32]){
    std::vector<uint8_t> v(data, data+len);
    bitcrypto::tx::tagged_hash(tag.c_str(), v, out32);
}

static inline void tapbranch(const uint8_t h1[32], const uint8_t h2[32], uint8_t out32[32]){
    std::array<uint8_t,64> buf{};
    const uint8_t* a = h1; const uint8_t* b = h2;
    if (std::lexicographical_compare(h2,h2+32,h1,h1+32)) { a = h2; b = h1; }
    for (int i=0;i<32;i++){ buf[i]=a[i]; buf[32+i]=b[i]; }
    tagged_hash_branch("TapBranch", buf.data(), buf.size(), out32);
}

static inline void build_taptree(const std::vector<std::array<uint8_t,32>>& leaves, uint8_t out32[32]){
    if (leaves.empty()){ for (int i=0;i<32;i++) out32[i]=0; return; }
    std::array<uint8_t,32> acc = leaves[0];
    uint8_t tmp[32];
    for (size_t i=1;i<leaves.size(); ++i){
        tapbranch(acc.data(), leaves[i].data(), tmp);
        for (int k=0;k<32;k++) acc[k]=tmp[k];
    }
    for (int k=0;k<32;k++) out32[k]=acc[k];
}

}} // ns
