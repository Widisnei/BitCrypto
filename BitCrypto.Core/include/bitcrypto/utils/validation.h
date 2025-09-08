#pragma once
// bitcrypto/utils/validation.h
// Validação de escalares e chaves privadas (range [1..n-1]).

#include <cstdint>
#include "../u256.h"
#include "../base.h"

namespace bitcrypto { namespace validate {

inline bool scalar_is_zero_or_ge_n(const U256& k){
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    // k >= n ? Faz k - n e observa o underflow
    uint64_t br=0;
    (void)subb64(k.v[0], N[0], br);
    (void)subb64(k.v[1], N[1], br);
    (void)subb64(k.v[2], N[2], br);
    (void)subb64(k.v[3], N[3], br);
    bool ge_n = (br==0);
    bool is_zero = (k.v[0]|k.v[1]|k.v[2]|k.v[3])==0ULL;
    return is_zero || ge_n;
}

inline bool priv_is_valid(const uint8_t be32[32]){
    U256 k = U256::from_be32(be32);
    return !scalar_is_zero_or_ge_n(k);
}

}} // ns
