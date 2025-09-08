#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "sha256.h"
namespace bitcrypto { namespace hash {
inline void sha256_tagged(const char* tag, const uint8_t* data, size_t len, uint8_t out[32]){
    uint8_t th[32]; sha256((const uint8_t*)tag, std::strlen(tag), th);
    SHA256Ctx c; sha256_init(c); sha256_update(c, th, 32); sha256_update(c, th, 32); if (data && len) sha256_update(c, data, len); sha256_final(c, out);
}
}}