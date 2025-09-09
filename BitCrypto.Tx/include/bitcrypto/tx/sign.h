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
    uint8_t sighash[32]; sighash_legacy_all(tx, index, scriptCode, hashType, sighash);
    ECDSA_Signature sig; if (!ecdsa_sign(priv32, sighash, sig, true)) return false;
    std::vector<uint8_t> der; bitcrypto::encoding::ecdsa_der_encode(sig.r, sig.s, der);
    std::vector<uint8_t> pushsig = der; pushsig.push_back((uint8_t)hashType);
    std::vector<uint8_t> scriptSig; push_data(pushsig, scriptSig); std::vector<uint8_t> pk(pub33, pub33+33); push_data(pk, scriptSig);
    tx.vin[index].scriptSig = scriptSig; tx.vin[index].witness.clear(); return true;
}

inline bool sign_p2wpkh(Transaction& tx, size_t index, const uint8_t priv32[32], uint64_t amount, uint32_t hashType){
    using namespace bitcrypto; using namespace bitcrypto::sign;
    uint8_t pub33[33], h160[20]; pubkey_hash160_from_priv(priv32, pub33, h160);
    // scriptCode é o script P2PKH CANÔNICO (BIP143) com o hash160 do pubkey
    std::vector<uint8_t> scriptCode = script_p2pkh(h160);
    uint8_t sighash[32]; sighash_segwit_v0_all(tx, index, scriptCode, amount, sighash);
    ECDSA_Signature sig; if (!ecdsa_sign(priv32, sighash, sig, true)) return false;
    std::vector<uint8_t> w0; bitcrypto::encoding::ecdsa_der_encode(sig.r, sig.s, w0); w0.push_back((uint8_t)hashType);
    std::vector<uint8_t> w1(pub33, pub33+33);
    tx.vin[index].scriptSig.clear(); tx.vin[index].witness = { std::move(w0), std::move(w1) };
    return true;
}


inline void serialize_der_sig_with_hashbyte(const bitcrypto::sign::ECDSA_Signature& sig, uint32_t hashType, std::vector<uint8_t>& out){
    bitcrypto::encoding::ecdsa_der_encode(sig.r, sig.s, out); out.push_back((uint8_t)hashType);
}

inline bool sign_input_p2wpkh(Transaction& tx, size_t index, const uint8_t priv32[32], const uint8_t h160[20], uint64_t amount, uint32_t hashType){
    using namespace bitcrypto; using namespace bitcrypto::sign;
    std::vector<uint8_t> scriptCode = script_p2pkh(h160);
    uint8_t sighash[32]; sighash_segwit_v0_all(tx, index, scriptCode, amount, sighash);
    ECDSA_Signature sig; if (!ecdsa_sign(priv32, sighash, sig, true)) return false;
    std::vector<uint8_t> w0; serialize_der_sig_with_hashbyte(sig, hashType, w0);
    U256 d = U256::from_be32(priv32); Secp256k1::scalar_mod_n(d); auto P = Secp256k1::derive_pubkey(d);
    uint8_t pub33[33]; size_t plen=0; encode_pubkey(P, true, pub33, plen);
    std::vector<uint8_t> w1(pub33, pub33+33);
    tx.vin[index].scriptSig.clear(); tx.vin[index].witness = { std::move(w0), std::move(w1) };
    return true;
}

inline bool sign_input_p2pkh(Transaction& tx, size_t index, const uint8_t priv32[32], const uint8_t h160[20], uint32_t hashType){
    using namespace bitcrypto; using namespace bitcrypto::sign;
    std::vector<uint8_t> scriptCode = script_p2pkh(h160);
    uint8_t sighash[32]; sighash_legacy_all(tx, index, scriptCode, hashType, sighash);
    ECDSA_Signature sig; if (!ecdsa_sign(priv32, sighash, sig, true)) return false;
    std::vector<uint8_t> pushsig; bitcrypto::encoding::ecdsa_der_encode(sig.r, sig.s, pushsig); pushsig.push_back((uint8_t)hashType);
    std::vector<uint8_t> scriptSig; push_data(pushsig, scriptSig);
    U256 d = U256::from_be32(priv32); Secp256k1::scalar_mod_n(d); auto P = Secp256k1::derive_pubkey(d);
    uint8_t pub33[33]; size_t plen=0; encode_pubkey(P, true, pub33, plen);
    std::vector<uint8_t> pk(pub33, pub33+plen); push_data(pk, scriptSig);
    tx.vin[index].scriptSig = scriptSig; tx.vin[index].witness.clear(); return true;
}

}} // ns
