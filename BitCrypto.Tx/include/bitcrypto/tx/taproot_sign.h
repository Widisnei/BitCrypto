#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include "bip341.h"
#include "taproot.h"
#include <bitcrypto/sign/schnorr.h>
#include <bitcrypto/hash/sha256.h>

namespace bitcrypto { namespace tx {

inline bool sign_input_p2tr_keypath(Transaction& tx, size_t in_idx,
                                    const uint8_t priv32[32],
                                    const std::vector<uint64_t>& amounts,
                                    const std::vector<std::vector<uint8_t>>& scriptPubKeys,
                                    uint32_t sighash_type){
    using namespace bitcrypto;
    if (in_idx>=tx.vin.size()) return false;
    U256 d = U256::from_be32(priv32); Secp256k1::scalar_mod_n(d); if (d.is_zero()) return false;
    auto P = Secp256k1::derive_pubkey(d);
    uint8_t pub[65]; size_t plen=0; encode_pubkey(P,true,pub,plen);
    uint8_t xonlyP[32]; std::memcpy(xonlyP, pub+1, 32);
    uint8_t zero32[32]={0};
    uint8_t tweaked_priv[32]; tap_tweak_seckey(priv32, xonlyP, zero32, tweaked_priv);
    uint32_t sh = sighash_type;
    uint8_t m[32]; bip341_sighash_keypath(tx, in_idx, amounts, scriptPubKeys, sh, m);
    sign::SchnorrSignature sig{};
    if (!sign::schnorr_sign_bip340(tweaked_priv, m, sig)) return false;
    std::vector<uint8_t> w0(64); std::memcpy(w0.data(), sig.bytes, 64);
    if ((sh & 0xFF) != 0x00){ w0.push_back((uint8_t)(sh & 0xFF)); }
    tx.vin[in_idx].witness.clear(); tx.vin[in_idx].witness.push_back(w0); tx.segwit=true; tx.set_segwit_if_any_witness();
    return true;
}

}} // ns
