#pragma once
#include "sha256.h"
#include "ripemd160.h"
namespace bitcrypto { namespace hash {
inline void hash160(const uint8_t* d,size_t n,uint8_t out20[20]){ uint8_t tmp[32]; sha256(d,n,tmp); ripemd160(tmp,32,out20); }
}}