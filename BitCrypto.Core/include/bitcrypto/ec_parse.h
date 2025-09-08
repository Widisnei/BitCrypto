#pragma once
#include <vector>
#include <cstdint>
#include "ec_secp256k1.h"
namespace bitcrypto {

inline bool parse_pubkey(const uint8_t* data, size_t len, ECPointA& out){
    if (len==33 && (data[0]==0x02 || data[0]==0x03)){
        // comprimida: recupere X e derive Y por sqrt, escolhendo paridade
        U256 x{}; for (int i=0;i<4;i++){ uint64_t w=0; for (int j=0;j<8;j++) w=(w<<8)|data[1+i*8+j]; x.v[3-i]=w; }
        Fp X = Fp::from_u256_nm(x);
        // y^2 = x^3 + 7
        Fp y2 = Fp::add(Fp::mul(Fp::mul(X,X), X), Secp256k1::b());
        Fp Y = Fp::sqrt(y2);
        // selecione paridade correta
        U256 ynm = Y.to_u256_nm(); bool odd = (ynm.v[0] & 1ULL)!=0ULL;
        bool want_odd = (data[0]==0x03);
        if (odd != want_odd){ Y = Fp::sub(Fp::zero(), Y); }
        out = ECPointA{X, Y, false};
        return Secp256k1::is_on_curve(out);
    } else if (len==65 && data[0]==0x04){
        U256 x{}, y{};
        for (int i=0;i<4;i++){ uint64_t w=0; for(int j=0;j<8;j++) w=(w<<8)|data[1+i*8+j]; x.v[3-i]=w; }
        for (int i=0;i<4;i++){ uint64_t w=0; for(int j=0;j<8;j++) w=(w<<8)|data[33+i*8+j]; y.v[3-i]=w; }
        Fp X = Fp::from_u256_nm(x); Fp Y = Fp::from_u256_nm(y);
        out = ECPointA{X,Y,false};
        return Secp256k1::is_on_curve(out);
    }
    return false;
}

} // ns
