#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <bitcrypto/hash/hmac_sha256.h>
#include <bitcrypto/u256.h>
namespace bitcrypto { namespace sign {
// RFC6979 HMAC-DRBG (SHA-256) — retorna k em [1,n-1] para secp256k1
inline void rfc6979_nonce(const uint8_t priv32[32], const uint8_t msg32[32], uint8_t out_k[32]){
    using namespace bitcrypto; using namespace bitcrypto::hash;
    uint8_t K[32]; std::memset(K, 0x00, 32);
    uint8_t V[32]; std::memset(V, 0x01, 32);
    uint8_t bx[64]; std::memcpy(bx, priv32, 32); std::memcpy(bx+32, msg32, 32);
    // K = HMAC(K, V || 0x00 || bx)
    uint8_t in1[97]; std::memcpy(in1, V, 32); in1[32]=0x00; std::memcpy(in1+33, bx, 64); hmac_sha256(K, 32, in1, 97, K);
    hmac_sha256(K, 32, V, 32, V);
    // K = HMAC(K, V || 0x01 || bx)
    uint8_t in2[97]; std::memcpy(in2, V, 32); in2[32]=0x01; std::memcpy(in2+33, bx, 64); hmac_sha256(K, 32, in2, 97, K);
    hmac_sha256(K, 32, V, 32, V);
    // loop
    while (true){
        // V = HMAC(K, V)
        hmac_sha256(K, 32, V, 32, V);
        std::memcpy(out_k, V, 32);
        // k = int(V) mod n; testa 1..n-1 com comparação bruta
        U256 k = U256::from_be32(out_k); Secp256k1::scalar_mod_n(k);
        if (!k.is_zero()){ // k ∈ [1, n-1]
            k.to_be32(out_k); return;
        }
        // K = HMAC(K, V || 0x00); V = HMAC(K, V);
        uint8_t in3[33]; std::memcpy(in3, V, 32); in3[32]=0x00; hmac_sha256(K, 32, in3, 33, K); hmac_sha256(K, 32, V, 32, V);
    }
}
}}