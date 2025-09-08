#pragma once
#include "base.h"
namespace bitcrypto {
struct U256{
    uint64_t v[4];
    BITCRYPTO_HD static inline U256 zero(){ return U256{{0,0,0,0}}; }
    BITCRYPTO_HD static inline U256 one(){ return U256{{1,0,0,0}}; }
    BITCRYPTO_HD inline bool is_zero() const { return (v[0]|v[1]|v[2]|v[3])==0; }
    static inline U256 from_be32(const uint8_t be[32]){
        U256 r = U256::zero();
        for (int i=0;i<4;i++){ uint64_t w=0; for (int j=0;j<8;j++) w=(w<<8)|be[i*8+j]; r.v[3-i]=w; }
        return r;
    }
    inline void to_be32(uint8_t out[32]) const {
        for (int i=0;i<4;i++){ uint64_t w=v[3-i]; for (int j=7;j>=0;j--) out[i*8+(7-j)]=(uint8_t)((w>>(j*8))&0xFF); }
    }
};
}