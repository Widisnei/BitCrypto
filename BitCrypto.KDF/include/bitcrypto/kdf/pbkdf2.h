#pragma once
#include "../BitCrypto.Hash/include/bitcrypto/hash/pbkdf2_hmac_sha512.h"
namespace bitcrypto { namespace kdf {
inline void pbkdf2_hmac_sha512(const uint8_t* P,size_t Plen,const uint8_t* S,size_t Slen,uint32_t c,uint8_t* DK,size_t dkLen){
    bitcrypto::hash::pbkdf2_hmac_sha512(P,Plen,S,Slen,c,DK,dkLen);
}
}}