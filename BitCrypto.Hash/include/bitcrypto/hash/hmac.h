#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "sha256.h"
namespace bitcrypto { namespace hash {
inline void hmac_sha256(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t out[32]){
    uint8_t k0[64]; if (keylen>64){ sha256(key, keylen, k0); std::memset(k0+32,0,32); } else { std::memset(k0,0,64); std::memcpy(k0,key,keylen); }
    uint8_t ipad[64], opad[64];
    for (int i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
    SHA256Ctx c; sha256_init(c); sha256_update(c, ipad, 64); if (datalen) sha256_update(c, data, datalen); uint8_t inner[32]; sha256_final(c, inner);
    sha256_init(c); sha256_update(c, opad, 64); sha256_update(c, inner, 32); sha256_final(c, out);
}
}}