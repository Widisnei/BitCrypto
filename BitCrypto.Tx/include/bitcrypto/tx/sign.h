#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/encoding/der.h>
#include <bitcrypto/encoding/b58check.h>
#include <bitcrypto/encoding/segwit.h>
#include <bitcrypto/encoding/taproot.h>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/sign/sign.h>
#include "tx.h"
#include "sighash.h"
#include "script.h"
#include "varint.h"

namespace bitcrypto { namespace tx {

inline void pubkey_hash160_from_priv(const uint8_t priv32[32], uint8_t pub33[33], uint8_t h160[20]){
    using namespace bitcrypto; U256 k = U256::from_be32(priv32); Secp256k1::scalar_mod_n(k); auto P = Secp256k1::derive_pubkey(k);
    size_t plen=0; encode_pubkey(P, true, pub33, plen); bitcrypto::hash::hash160(pub33, 33, h160);
}

inline void xonly_from_priv(const uint8_t priv32[32], uint8_t x32[32]){
    using namespace bitcrypto; U256 k = U256::from_be32(priv32); Secp256k1::scalar_mod_n(k); auto P = Secp256k1::derive_pubkey(k);
    // taproot x-only (y par)
    bool neg=false; auto Pa = bitcrypto::encoding::normalize_even_y(P, x32, neg);
    (void)Pa;
}

inline bool sign_p2pkh(Transaction& tx, size_t index, const uint8_t priv32[32], uint32_t hashType){
    using namespace bitcrypto; using namespace bitcrypto::sign;
    uint8_t pub33[33], h160[20]; pubkey_hash160_from_priv(priv32, pub33, h160);
    std::vector<uint8_t> scriptCode = script_p2pkh(h160);
    std::vector<uint8_t> pre; legacy_sighash_preimage(tx, index, scriptCode, hashType, pre);
    uint8_t sighash[32]; bitcrypto::hash::sha256(pre.data(), pre.size(), sighash); bitcrypto::hash::sha256(sighash, 32, sighash);
    ECDSA_Signature sig; if (!ecdsa_sign(priv32, sighash, sig, true)) return false;
    uint8_t der[80]; size_t derlen=0; bitcrypto::encoding::ecdsa_sig_to_der(sig, der, derlen);
    std::vector<uint8_t> pushsig(der, der+derlen); pushsig.push_back((uint8_t)hashType);
    std::vector<uint8_t> scriptSig; push_data(pushsig, scriptSig); std::vector<uint8_t> pk(pub33, pub33+33); push_data(pk, scriptSig);
    tx.vin[index].scriptSig = scriptSig; tx.vin[index].witness.clear(); return true;
}

inline bool sign_p2wpkh(Transaction& tx, size_t index, const uint8_t priv32[32], uint64_t amount, uint32_t hashType){
    using namespace bitcrypto; using namespace bitcrypto::sign;
    uint8_t pub33[33], h160[20]; pubkey_hash160_from_priv(priv32, pub33, h160);
    // scriptCode é o script P2PKH CANÔNICO (BIP143) com o hash160 do pubkey
    std::vector<uint8_t> scriptCode = script_p2pkh(h160);
    uint8_t sighash[32]; bip143_sighash(tx, index, scriptCode, amount, hashType, sighash);
    ECDSA_Signature sig; if (!ecdsa_sign(priv32, sighash, sig, true)) return false;
    uint8_t der[80]; size_t derlen=0; bitcrypto::encoding::ecdsa_sig_to_der(sig, der, derlen);
    std::vector<uint8_t> w0(der, der+derlen); w0.push_back((uint8_t)hashType);
    std::vector<uint8_t> w1(pub33, pub33+33);
    tx.vin[index].scriptSig.clear(); tx.vin[index].witness = { std::move(w0), std::move(w1) };
    return true;
}

inline bool sign_p2tr_keypath(Transaction& tx, size_t index, const uint8_t priv32[32], uint64_t amount, uint32_t hashType){
    using namespace bitcrypto; using namespace bitcrypto::sign;
    uint8_t x32[32]; xonly_from_priv(priv32, x32);
    uint8_t msg[32]; bip341_sighash_keypath(tx, index, amount, hashType & 0xff, msg);
    uint8_t sig64[64]; if (!schnorr_sign_bip340(priv32, msg, nullptr, sig64)) return false;
    std::vector<uint8_t> w0(sig64, sig64+64);
    if ((hashType & 0xff) != 0x00) w0.push_back((uint8_t)(hashType & 0xff));
    tx.vin[index].scriptSig.clear(); tx.vin[index].witness = { std::move(w0) };
    return true;
}

}} // ns
