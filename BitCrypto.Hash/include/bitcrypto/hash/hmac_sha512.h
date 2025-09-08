#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "sha512.h"
namespace bitcrypto { namespace hash {
inline void hmac_sha512(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen, uint8_t out[64]){
    uint8_t k0[128]; if (keylen>128){ sha512(key,keylen,out); std::memset(k0,0,128); std::memcpy(k0,out,64); } else { std::memset(k0,0,128); if(key&&keylen) std::memcpy(k0,key,keylen); }
    uint8_t ipad[128], opad[128]; for(int i=0;i<128;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
    uint8_t inner[64]; SHA512Ctx c; sha512_init(c); sha512_update(c, ipad, 128); if (msg && msglen) sha512_update(c, msg, msglen); sha512_final(c, inner);
    sha512_init(c); sha512_update(c, opad, 128); sha512_update(c, inner, 64); sha512_final(c, out);
}
}}