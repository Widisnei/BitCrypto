#pragma once
#include "sha256.h"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace bitcrypto { namespace hash {

inline void tagged_sha256(const char* tag, const uint8_t* msg, size_t msg_len, uint8_t out32[32]){
    uint8_t th[32];
    sha256(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag), th);
    // buffer: th || th || msg
    std::vector<uint8_t> buf; buf.reserve(64 + msg_len);
    buf.insert(buf.end(), th, th+32);
    buf.insert(buf.end(), th, th+32);
    buf.insert(buf.end(), msg, msg + msg_len);
    sha256(buf.data(), buf.size(), out32);
}

}} // ns
