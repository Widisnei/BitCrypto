#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "hmac_sha512.h"
namespace bitcrypto { namespace hash {
// PBKDF2-HMAC-SHA512 (RFC 8018)
inline void pbkdf2_hmac_sha512(const uint8_t* P, size_t Plen, const uint8_t* S, size_t Slen, uint32_t c, uint8_t* DK, size_t dkLen){
    uint32_t hLen = 64; uint32_t l = (uint32_t)((dkLen + hLen - 1)/hLen);
    std::vector<uint8_t> T(hLen), U(hLen); std::vector<uint8_t> Si(Slen+4);
    std::memcpy(Si.data(), S, Slen);
    for (uint32_t i=1;i<=l;i++){
        Si[Slen+0]=(uint8_t)(i>>24); Si[Slen+1]=(uint8_t)(i>>16); Si[Slen+2]=(uint8_t)(i>>8); Si[Slen+3]=(uint8_t)i;
        hmac_sha512(P, Plen, Si.data(), Si.size(), U.data());
        std::memcpy(T.data(), U.data(), hLen);
        for (uint32_t j=2;j<=c;j++){ hmac_sha512(P, Plen, U.data(), hLen, U.data()); for (uint32_t k=0;k<hLen;k++) T[k]^=U[k]; }
        size_t offset = (size_t)(i-1)*hLen; size_t to_copy = (offset+hLen<=dkLen)? hLen : (dkLen - offset);
        std::memcpy(DK + offset, T.data(), to_copy);
    }
}
}}