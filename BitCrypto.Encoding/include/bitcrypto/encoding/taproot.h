#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "bech32.h"
#include "segwit.h"
#include "../hash/tagged_hash.h"
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
namespace bitcrypto { namespace encoding {
inline bitcrypto::ECPointA normalize_even_y(const bitcrypto::ECPointA& A, uint8_t out32[32], bool& negated){
    using namespace bitcrypto; U256 y=A.y.to_u256_nm(); bool odd=(y.v[0]&1ULL)!=0ULL; ECPointA P=A; if(odd){ P.y = Fp::sub(Fp::zero(), P.y); negated=true; } else { negated=false; }
    U256 x=P.x.to_u256_nm(); x.to_be32(out32); return P;
}
inline std::string p2tr_from_priv(const uint8_t priv32_be[32], bool testnet){
    using namespace bitcrypto; using namespace bitcrypto::hash;
    U256 k=U256::from_be32(priv32_be); auto P=Secp256k1::derive_pubkey(k);
    uint8_t xonly[32]; bool neg=false; auto Peven = normalize_even_y(P, xonly, neg);
    uint8_t t32[32]; sha256_tagged("TapTweak", xonly, 32, t32); U256 t=U256::from_be32(t32); Secp256k1::scalar_mod_n(t);
    ECPointJ tG=Secp256k1::scalar_mul(t, Secp256k1::G()); ECPointJ Qj=Secp256k1::add(Secp256k1::to_jacobian(Peven), tG); ECPointA Q=Secp256k1::to_affine(Qj);
    uint8_t qx[32]; bool _; normalize_even_y(Q, qx, _); std::vector<uint8_t> prog(qx, qx+32); std::vector<uint8_t> prog5; convert_bits(prog5, 5, prog, 8, true);
    std::vector<uint8_t> data; data.push_back(1); data.insert(data.end(), prog5.begin(), prog5.end()); return bech32_encode(segwit_hrp(testnet), data, /*bech32m=*/true);
}
inline bool p2tr_decode_address(const std::string& addr, bool& is_testnet, uint8_t out32[32]){
    std::string hrp; int ver=0; std::vector<uint8_t> prog; if (!segwit_decode_address(addr, hrp, ver, prog)) return false; if (ver!=1 || prog.size()!=32) return false;
    is_testnet = (hrp=="tb"); for(int i=0;i<32;i++) out32[i]=prog[i]; return true;
}
}}