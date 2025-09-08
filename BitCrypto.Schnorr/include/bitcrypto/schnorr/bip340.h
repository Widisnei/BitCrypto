
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include "../../Hash/include/bitcrypto/hash/sha256.h"
#include "../../EC/include/bitcrypto/ec/secp256k1.h"

namespace bitcrypto { namespace schnorr {

static inline void hex2bin(const char* s, std::vector<uint8_t>& out){
    auto h2n=[](char c)->int{ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return -1; };
    size_t n=strlen(s); out.clear(); out.reserve(n/2);
    for (size_t i=0;i+1<n;i+=2){ int a=h2n(s[i]), b=h2n(s[i+1]); if(a<0||b<0){ out.clear(); return; } out.push_back((uint8_t)((a<<4)|b)); }
}

static inline void be32o(uint32_t x, uint8_t* o){ o[0]=(uint8_t)(x>>24); o[1]=(uint8_t)(x>>16); o[2]=(uint8_t)(x>>8); o[3]=(uint8_t)x; }


static inline bool bip340_verify(const uint8_t pubx[32], const uint8_t msg[32], const uint8_t sig[64]){
    using namespace bitcrypto::ec;
    using namespace bitcrypto::hash;
    // Parse r,s
    Fe r_fe, px; fe_from_bytes(r_fe, sig); fe_from_bytes(px, pubx);
    Fe p = fe_p();
    if (fe_cmp_raw(r_fe,p)>=0) return false; // r < p
    // s < n check (canonical)
    static const uint8_t n_be[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
    auto lt_be = [&](const uint8_t a[32], const uint8_t b[32])->bool{
        for (int i=0;i<32;i++){ if (a[i]!=b[i]) return a[i]<b[i]; }
        return false; // equal => not less
    };
    const uint8_t* s32 = sig+32;
    if (!lt_be(s32, n_be)) return false;
    // Lift P from x-only (even y)
    PointA P; if (!lift_x_even_y(P, px)) return false;
    // e = int(tagged_hash("BIP0340/challenge", r||px||m)) mod n (we use 32 bytes; scalar_mul naturally wraps by group order)
    uint8_t data[96]; memcpy(data, sig, 32); memcpy(data+32, pubx, 32); memcpy(data+64, msg, 32);
    uint8_t e32[32]; SHA256::tag_hash("BIP0340/challenge", data, 96, e32);
    // Compute s*G
    PointA G; secp_g(G); PointJ sG; scalar_mul(sG, G, s32);
    // Compute e*P
    PointJ eP; scalar_mul(eP, P, e32);
    // R = sG - eP = sG + (-eP)
    PointA eP_aff; pa_from_jacobian(eP_aff, eP);
    if (eP_aff.inf) return false;
    // negate y
    Fe ny; Fe pp = fe_p(); fe_sub(ny, pp, eP_aff.y); eP_aff.y = ny;
    PointJ R; pj_add_mixed(R, sG, eP_aff);
    if (pj_is_inf(R)) return false;
    PointA Ra; pa_from_jacobian(Ra, R);
    if (fe_is_odd(Ra.y)) return false; // even y
    // x(R) == r ?
    if (!fe_eq(Ra.x, r_fe)) return false;
    return true;
}

}} // ns
