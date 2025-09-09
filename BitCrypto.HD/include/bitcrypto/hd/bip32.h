#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/field_n.h>
#include <bitcrypto/hash/hmac_sha512.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/encoding/b58check.h>

namespace bitcrypto { namespace hd {

enum class Network: uint8_t { MAIN=0, TEST=1 };

struct ExtPriv{
    uint8_t depth;
    uint32_t parent_fingerprint;
    uint32_t child_index;
    uint8_t chain_code[32];
    uint8_t key[32]; // big-endian bytes
};

struct ExtPub{
    uint8_t depth;
    uint32_t parent_fingerprint;
    uint32_t child_index;
    uint8_t chain_code[32];
    uint8_t pubkey[33]; // compressed
};

inline void ser32(uint32_t x, uint8_t out[4]){ out[0]=(uint8_t)(x>>24); out[1]=(uint8_t)(x>>16); out[2]=(uint8_t)(x>>8); out[3]=(uint8_t)x; }
inline uint32_t fingerprint_from_pub(const uint8_t pub33[33]){ uint8_t h160[20]; bitcrypto::hash::hash160(pub33,33,h160); return (uint32_t)h160[0]<<24 | (uint32_t)h160[1]<<16 | (uint32_t)h160[2]<<8 | (uint32_t)h160[3]; }

// Version bytes
static inline uint32_t ver_xprv_main(){ return 0x0488ADE4U; }
static inline uint32_t ver_xpub_main(){ return 0x0488B21EU; }
static inline uint32_t ver_xprv_test(){ return 0x04358394U; }
static inline uint32_t ver_xpub_test(){ return 0x043587CFU; }

inline bool master_from_seed(const uint8_t* seed, size_t seedlen, ExtPriv& out){
    static const char* key="Bitcoin seed"; uint8_t I[64];
    bitcrypto::hash::hmac_sha512((const uint8_t*)key, std::strlen(key), seed, seedlen, I);
    bitcrypto::U256 il=bitcrypto::U256::from_be32(I); bitcrypto::Secp256k1::scalar_mod_n(il);
    if (il.is_zero()) return false;
    out.depth=0; out.parent_fingerprint=0; out.child_index=0;
    std::memcpy(out.key, I, 32); std::memcpy(out.chain_code, I+32, 32);
    return true;
}

inline bool ckd_priv(const ExtPriv& parent, uint32_t index, ExtPriv& child){
    using namespace bitcrypto;
    bool hardened = (index & 0x80000000U)!=0;
    uint8_t data[1+33+4]; size_t dlen=0;
    if (hardened){ data[0]=0x00; std::memcpy(data+1, parent.key, 32); dlen=33; }
    else {
        U256 d=U256::from_be32(parent.key); Secp256k1::scalar_mod_n(d);
        auto P=Secp256k1::derive_pubkey(d); uint8_t pub[65]; size_t pl=0; encode_pubkey(P,true,pub,pl);
        std::memcpy(data, pub, 33); dlen=33;
    }
    data[dlen+0]=(uint8_t)(index>>24); data[dlen+1]=(uint8_t)(index>>16); data[dlen+2]=(uint8_t)(index>>8); data[dlen+3]=(uint8_t)index; dlen+=4;
    uint8_t I[64]; bitcrypto::hash::hmac_sha512(parent.chain_code,32,data,dlen,I);
    U256 il=U256::from_be32(I); Secp256k1::scalar_mod_n(il); if (il.is_zero()) return false;
    U256 k=U256::from_be32(parent.key); Secp256k1::scalar_mod_n(k);
    uint64_t c=0; U256 kch{{ addc64(il.v[0],k.v[0],c), addc64(il.v[1],k.v[1],c), addc64(il.v[2],k.v[2],c), addc64(il.v[3],k.v[3],c) }};
    kch = u256_mod_n(kch); if (kch.is_zero()) return false;
    child.depth = (uint8_t)(parent.depth + 1);
    uint8_t pubp[65]; size_t pl=0; auto Pp=Secp256k1::derive_pubkey(k); encode_pubkey(Pp,true,pubp,pl);
    child.parent_fingerprint = fingerprint_from_pub(pubp);
    child.child_index = index;
    uint8_t be[32]; kch.to_be32(be); std::memcpy(child.key, be, 32);
    std::memcpy(child.chain_code, I+32, 32);
    return true;
}

inline bool neuter(const ExtPriv& xprv, ExtPub& xpub){
    using namespace bitcrypto;
    U256 k=U256::from_be32(xprv.key); Secp256k1::scalar_mod_n(k);
    auto P=Secp256k1::derive_pubkey(k); uint8_t pub[65]; size_t pl=0; encode_pubkey(P,true,pub,pl);
    xpub.depth=xprv.depth; xpub.parent_fingerprint=xprv.parent_fingerprint; xpub.child_index=xprv.child_index;
    std::memcpy(xpub.chain_code, xprv.chain_code, 32); std::memcpy(xpub.pubkey, pub, 33);
    return true;
}

// sqrt exponent: (p+1)/4 for secp256k1 prime
inline bitcrypto::U256 sqrt_exponent(){
    return bitcrypto::U256{0xFFFFFFFFBFFFFF0CULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x3FFFFFFFFFFFFFFFULL};
}

inline bool ckd_pub(const ExtPub& parent, uint32_t index, ExtPub& child){
    if (index & 0x80000000U) return false; // hardened não permitido
    using namespace bitcrypto;
    // Parse compressed parent pubkey
    if (!(parent.pubkey[0]==0x02 || parent.pubkey[0]==0x03)) return false;
    uint8_t xbe[32]; std::memcpy(xbe, parent.pubkey+1, 32);
    U256 x = U256::from_be32(xbe);
    Fp X = Fp::from_u256_nm(x);
    Fp y2 = Fp::add(Fp::mul(Fp::mul(X,X),X), Secp256k1::b());
    Fp y = Fp::pow(y2, sqrt_exponent());
    U256 yu = y.to_u256_nm(); bool odd = (yu.v[0] & 1ULL)!=0ULL;
    if ((parent.pubkey[0]==0x03) != odd) y = Fp::sub(Fp::zero(), y);
    ECPointA P{X,y,false};

    // I = HMAC-SHA512(cc, serP(P) || ser32(i))
    uint8_t data[33+4]; std::memcpy(data, parent.pubkey, 33);
    data[33]=(uint8_t)(index>>24); data[34]=(uint8_t)(index>>16); data[35]=(uint8_t)(index>>8); data[36]=(uint8_t)index;
    uint8_t I[64]; bitcrypto::hash::hmac_sha512(parent.chain_code,32,data,37,I);
    U256 il=U256::from_be32(I); Secp256k1::scalar_mod_n(il); if (il.is_zero()) return false;

    // child = IL*G + parent
    ECPointJ childJ = Secp256k1::add(Secp256k1::scalar_mul(il, Secp256k1::G()), Secp256k1::to_jacobian(P));
    ECPointA Ca = Secp256k1::to_affine(childJ); if (Ca.infinity) return false;

    uint8_t pub[65]; size_t pl=0; encode_pubkey(Ca, true, pub, pl);

    child.depth = (uint8_t)(parent.depth + 1);
    child.parent_fingerprint = fingerprint_from_pub(parent.pubkey);
    child.child_index = index;
    std::memcpy(child.chain_code, I+32, 32);
    std::memcpy(child.pubkey, pub, 33);
    return true;
}

inline std::string to_base58_xprv(const ExtPriv& xprv, Network net){
    uint8_t ver[4]; if(net==Network::MAIN){ ver[0]=0x04; ver[1]=0x88; ver[2]=0xAD; ver[3]=0xE4; } else { ver[0]=0x04; ver[1]=0x35; ver[2]=0x83; ver[3]=0x94; }
    std::vector<uint8_t> p; p.insert(p.end(), ver, ver+4); p.push_back(xprv.depth);
    uint8_t tmp[4]; ser32(xprv.parent_fingerprint,tmp); p.insert(p.end(),tmp,tmp+4); ser32(xprv.child_index,tmp); p.insert(p.end(),tmp,tmp+4);
    p.insert(p.end(), xprv.chain_code, xprv.chain_code+32);
    p.push_back(0x00); p.insert(p.end(), xprv.key, xprv.key+32);
    return bitcrypto::encoding::base58check_encode(p);
}

inline std::string to_base58_xpub(const ExtPub& xpub, Network net){
    uint8_t ver[4]; if(net==Network::MAIN){ ver[0]=0x04; ver[1]=0x88; ver[2]=0xB2; ver[3]=0x1E; } else { ver[0]=0x04; ver[1]=0x35; ver[2]=0x87; ver[3]=0xCF; }
    std::vector<uint8_t> p; p.insert(p.end(), ver, ver+4); p.push_back(xpub.depth);
    uint8_t tmp[4]; ser32(xpub.parent_fingerprint,tmp); p.insert(p.end(),tmp,tmp+4); ser32(xpub.child_index,tmp); p.insert(p.end(),tmp,tmp+4);
    p.insert(p.end(), xpub.chain_code, xpub.chain_code+32);
    p.insert(p.end(), xpub.pubkey, xpub.pubkey+33);
    return bitcrypto::encoding::base58check_encode(p);
}

inline bool from_base58_xprv(const std::string& s, ExtPriv& out, Network& net){
    std::vector<uint8_t> p; if (!bitcrypto::encoding::base58check_decode(s, p)) return false;
    if (p.size()!=78) return false;
    uint32_t ver = (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | (uint32_t)p[3];
    if (ver==ver_xprv_main()) net=Network::MAIN;
    else if (ver==ver_xprv_test()) net=Network::TEST;
    else return false;
    out.depth = p[4];
    out.parent_fingerprint = (uint32_t)p[5]<<24 | (uint32_t)p[6]<<16 | (uint32_t)p[7]<<8 | (uint32_t)p[8];
    out.child_index        = (uint32_t)p[9]<<24 | (uint32_t)p[10]<<16 | (uint32_t)p[11]<<8 | (uint32_t)p[12];
    std::memcpy(out.chain_code, &p[13], 32);
    if (p[45]!=0x00) return false;
    std::memcpy(out.key, &p[46], 32);
    return true;
}

inline bool from_base58_xpub(const std::string& s, ExtPub& out, Network& net){
    std::vector<uint8_t> p; if (!bitcrypto::encoding::base58check_decode(s, p)) return false;
    if (p.size()!=78) return false;
    uint32_t ver = (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | (uint32_t)p[3];
    if (ver==ver_xpub_main()) net=Network::MAIN;
    else if (ver==ver_xpub_test()) net=Network::TEST;
    else return false;
    out.depth = p[4];
    out.parent_fingerprint = (uint32_t)p[5]<<24 | (uint32_t)p[6]<<16 | (uint32_t)p[7]<<8 | (uint32_t)p[8];
    out.child_index        = (uint32_t)p[9]<<24 | (uint32_t)p[10]<<16 | (uint32_t)p[11]<<8 | (uint32_t)p[12];
    std::memcpy(out.chain_code, &p[13], 32);
    std::memcpy(out.pubkey, &p[45], 33);
    if (!(out.pubkey[0]==0x02 || out.pubkey[0]==0x03)) return false;
    return true;
}

}} // ns
