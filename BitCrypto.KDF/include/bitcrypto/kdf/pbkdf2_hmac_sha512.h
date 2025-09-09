#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <bitcrypto/hash/hmac_sha512.h>
namespace bitcrypto { namespace kdf {
// PBKDF2-HMAC-SHA512 (RFC 8018). Iterations >= 1.
inline bool pbkdf2_hmac_sha512(const uint8_t* password, size_t pwlen,
                               const uint8_t* salt, size_t saltlen,
                               uint32_t iterations,
                               uint8_t* out, size_t dkLen){
    using namespace bitcrypto::hash;
    if (iterations==0) return false;
    uint32_t blocks = (uint32_t)((dkLen + 63)/64);
    std::vector<uint8_t> U(64), T(64);
    for (uint32_t i=1;i<=blocks;i++){
        // U1 = HMAC(pw, salt || INT(i))
        uint8_t ib[4]={(uint8_t)(i>>24),(uint8_t)(i>>16),(uint8_t)(i>>8),(uint8_t)i};
        std::vector<uint8_t> s(salt, salt+saltlen); s.insert(s.end(), ib, ib+4);
        hmac_sha512(password, pwlen, s.data(), s.size(), U.data());
        std::memcpy(T.data(), U.data(), 64);
        for (uint32_t j=2;j<=iterations;j++){
            hmac_sha512(password, pwlen, U.data(), 64, U.data());
            for (int k=0;k<64;k++) T[k]^=U[k];
        }
        size_t off = (size_t)(i-1)*64;
        size_t to_copy = (dkLen - off > 64) ? 64 : (dkLen - off);
        std::memcpy(out + off, T.data(), to_copy);
    }
    return true;
}
}}