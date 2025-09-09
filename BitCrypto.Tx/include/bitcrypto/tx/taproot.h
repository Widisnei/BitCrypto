#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/sign/schnorr.h>
#include "tx.h"

// Implementação Taproot (BIP340/341):
// - tagged_hash(tag, msg) = SHA256(SHA256(tag)||SHA256(tag)||msg)
// - tweak: t = int(tagged_hash("TapTweak", xonly(P) || merkle_root?)) mod n
// - Q = P + t*G; sk' = (sk + t) mod n; se y(Q) ímpar, sk' = n - sk' (BIP340 exige Y par)
namespace bitcrypto { namespace tx {

inline void sha256_tag(const char* tag, std::vector<uint8_t>& out32){
    using namespace bitcrypto::hash;
    uint8_t th[32]; sha256((const uint8_t*)tag, std::strlen(tag), th);
    out32.assign(th, th+32);
}
inline void tagged_hash(const char* tag, const std::vector<uint8_t>& msg, uint8_t out32[32]){
    using namespace bitcrypto::hash;
    uint8_t th[32]; sha256((const uint8_t*)tag, std::strlen(tag), th);
    std::vector<uint8_t> buf; buf.reserve(64 + msg.size());
    buf.insert(buf.end(), th, th+32); buf.insert(buf.end(), th, th+32); buf.insert(buf.end(), msg.begin(), msg.end());
    sha256(buf.data(), buf.size(), out32);
}

// Extrai X (32B) e paridade de Y de um ponto afim.
inline void xonly_from_point(const bitcrypto::ECPointA& P, uint8_t x32[32], bool& y_odd){
    bitcrypto::U256 xu = P.X.to_u256_nm();
    xu.to_be32(x32);
    bitcrypto::U256 yu = P.Y.to_u256_nm();
    y_odd = (yu.v[0] & 1ULL) != 0ULL;
}

// Dado X (32B), eleva para ponto com Y par (BIP340).
inline bool lift_x_even(const uint8_t x32[32], bitcrypto::ECPointA& P){
    using namespace bitcrypto;
    U256 x = U256::from_be32(x32);
    Fp X = Fp::from_u256_nm(x);
    // y^2 = x^3 + 7 mod p
    Fp y2 = Fp::add(Fp::mul(Fp::mul(X,X),X), Secp256k1::b());
    // sqrt via (p+1)/4, já disponível via exp
    // expoente = (p+1)/4
    U256 e_sqrt{{0xFFFFFFFFBFFFFF0CULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x3FFFFFFFFFFFFFFFULL}};
    Fp Y = Fp::pow(y2, e_sqrt);
    if (Fp::is_zero(Y) && !Fp::is_zero(y2)) return false;
    // força Y par
    U256 yu = Y.to_u256_nm(); if ((yu.v[0] & 1ULL) != 0ULL) Y = Fp::sub(Fp::zero(), Y);
    P = ECPointA{X, Y, false};
    return true;
}

// Tweak de chave secreta para Taproot (key-path). Se merkle_root for null, usa apenas xonly(P).
inline bool taproot_tweak_seckey(const uint8_t seckey32[32], const uint8_t* merkle_root32_or_null, uint8_t out32[32]){
    using namespace bitcrypto;
    // normaliza sk para P com Y par (BIP340)
    U256 d = U256::from_be32(seckey32); Secp256k1::scalar_mod_n(d); if (d.is_zero()) return false;
    auto P = Secp256k1::derive_pubkey(d);
    // garante Y par ajustando d se necessário
    U256 yu = P.Y.to_u256_nm(); if (yu.v[0] & 1ULL){ d = U256::sub(bitcrypto::Secp256k1::n(), d); P = Secp256k1::neg(P); }
    // xonly(P)
    uint8_t px[32]; bool _odd=false; xonly_from_point(P, px, _odd);
    // tagged_hash("TapTweak", px || merkle)
    std::vector<uint8_t> msg; msg.insert(msg.end(), px, px+32);
    if (merkle_root32_or_null){ msg.insert(msg.end(), merkle_root32_or_null, merkle_root32_or_null+32); }
    uint8_t th[32]; tagged_hash("TapTweak", msg, th);
    U256 t = U256::from_be32(th); Secp256k1::scalar_mod_n(t);
    // sk' = (d + t) mod n
    uint64_t c=0;
    U256 skp{{ addc64(d.v[0], t.v[0], c), addc64(d.v[1], t.v[1], c), addc64(d.v[2], t.v[2], c), addc64(d.v[3], t.v[3], c) }};
    skp = u256_mod_n(skp); if (skp.is_zero()) return false;
    // Q = P + t*G
    auto Q = Secp256k1::add(Secp256k1::to_jacobian(P), Secp256k1::scalar_mul(t, Secp256k1::G()));
    auto Qa = Secp256k1::to_affine(Q);
    // força Y(Q) par ajustando sk'
    U256 yuQ = Qa.Y.to_u256_nm(); if (yuQ.v[0] & 1ULL){ skp = U256::sub(Secp256k1::n(), skp); }
    skp.to_be32(out32);
    return true;
}

// Sighash Taproot (key-path, sem annex, ext_flag=0), conforme BIP341 SigMsg().
inline void taproot_sighash_keypath(const bitcrypto::tx::Transaction& tx, size_t in_idx,
                                    const std::vector<uint64_t>& input_amounts,
                                    const std::vector<std::vector<uint8_t>>& input_scriptpubkeys,
                                    uint32_t sighash, uint8_t out32[32]){
    using namespace bitcrypto::encoding;
    using namespace bitcrypto::hash;
    // Pré-hashes
    uint8_t sha_prevouts[32], sha_amounts[32], sha_scriptpubkeys[32], sha_sequences[32], sha_outputs[32];
    bool anyone = (sighash & 0x80)!=0;
    bool none = ((sighash & 0x03)==0x02);
    bool single = ((sighash & 0x03)==0x03);
    // sha_prevouts (concat outpoints)
    if (!anyone){
        std::vector<uint8_t> buf;
        for (const auto& in: tx.vin){
            buf.insert(buf.end(), in.prevout.txid, in.prevout.txid+32);
            for (int i=0;i<4;i++) buf.push_back((uint8_t)((in.prevout.vout>>(8*i))&0xFF));
        }
        sha256(buf.data(), buf.size(), sha_prevouts);
    } else std::memset(sha_prevouts,0,32);
    // sha_amounts
    if (!anyone){
        std::vector<uint8_t> buf; for (auto a: input_amounts){ for (int i=0;i<8;i++) buf.push_back((uint8_t)((a>>(8*i))&0xFF)); }
        sha256(buf.data(), buf.size(), sha_amounts);
    } else std::memset(sha_amounts,0,32);
    // sha_scriptpubkeys (serialize as script inside CTxOut: varint(len)||script)
    if (!anyone){
        std::vector<uint8_t> buf;
        for (auto& spk: input_scriptpubkeys){ write_varint(buf, spk.size()); buf.insert(buf.end(), spk.begin(), spk.end()); }
        sha256(buf.data(), buf.size(), sha_scriptpubkeys);
    } else std::memset(sha_scriptpubkeys,0,32);
    // sha_sequences
    if (!anyone && (none || single)){
        std::vector<uint8_t> buf; for (const auto& in: tx.vin){ for (int i=0;i<4;i++) buf.push_back((uint8_t)((in.sequence>>(8*i))&0xFF)); }
        sha256(buf.data(), buf.size(), sha_sequences);
    } else if (!anyone && !(none||single)){
        // BIP341 exige sha_sequences quando NONE ou SINGLE; porém em ALL não usa? A especificação usa sha_sequences sempre que not ANYONECANPAY
        std::vector<uint8_t> buf; for (const auto& in: tx.vin){ for (int i=0;i<4;i++) buf.push_back((uint8_t)((in.sequence>>(8*i))&0xFF)); }
        sha256(buf.data(), buf.size(), sha_sequences);
    } else std::memset(sha_sequences,0,32);
    // sha_outputs
    if (!none && !single){
        std::vector<uint8_t> buf;
        for (const auto& o: tx.vout){
            for (int i=0;i<8;i++) buf.push_back((uint8_t)((o.value>>(8*i))&0xFF));
            write_varint(buf, o.scriptPubKey.size()); buf.insert(buf.end(), o.scriptPubKey.begin(), o.scriptPubKey.end());
        }
        sha256(buf.data(), buf.size(), sha_outputs);
    } else if (single && in_idx < tx.vout.size()){
        std::vector<uint8_t> buf;
        const auto& o = tx.vout[in_idx];
        for (int i=0;i<8;i++) buf.push_back((uint8_t)((o.value>>(8*i))&0xFF));
        write_varint(buf, o.scriptPubKey.size()); buf.insert(buf.end(), o.scriptPubKey.begin(), o.scriptPubKey.end());
        sha256(buf.data(), buf.size(), sha_outputs);
    } else std::memset(sha_outputs,0,32);

    // Constrói SigMsg(hash_type, ext_flag=0)
    std::vector<uint8_t> m;
    // hash_type (1)
    m.push_back((uint8_t)(sighash & 0xFF));
    // nVersion (4) + nLockTime (4)
    for (int i=0;i<4;i++) m.push_back((uint8_t)((tx.version>>(8*i))&0xFF));
    for (int i=0;i<4;i++) m.push_back((uint8_t)((tx.locktime>>(8*i))&0xFF));
    // aggregates
    if (!anyone){
        m.insert(m.end(), sha_prevouts, sha_prevouts+32);
        m.insert(m.end(), sha_amounts, sha_amounts+32);
        m.insert(m.end(), sha_scriptpubkeys, sha_scriptpubkeys+32);
        m.insert(m.end(), sha_sequences, sha_sequences+32);
    }
    if (!none && !single){
        m.insert(m.end(), sha_outputs, sha_outputs+32);
    } else if (single && in_idx < tx.vout.size()){
        m.insert(m.end(), sha_outputs, sha_outputs+32);
    }
    // Data sobre a entrada
    uint8_t spend_type = 0; // ext_flag=0, annex ausente
    m.push_back(spend_type);
    if (anyone){
        const auto& in = tx.vin[in_idx];
        m.insert(m.end(), in.prevout.txid, in.prevout.txid+32);
        for (int i=0;i<4;i++) m.push_back((uint8_t)((in.prevout.vout>>(8*i))&0xFF));
        // amount + scriptPubKey + sequence (da entrada atual)
        uint64_t amt = input_amounts[in_idx]; for (int i=0;i<8;i++) m.push_back((uint8_t)((amt>>(8*i))&0xFF));
        const auto& spk = input_scriptpubkeys[in_idx]; write_varint(m, spk.size()); m.insert(m.end(), spk.begin(), spk.end());
        for (int i=0;i<4;i++) m.push_back((uint8_t)((in.sequence>>(8*i))&0xFF));
    } else {
        // input_index
        uint32_t ii = (uint32_t)in_idx; for (int i=0;i<4;i++) m.push_back((uint8_t)((ii>>(8*i))&0xFF));
    }

    // Epoch prefix 0x00 e hash tag "TapSighash"
    std::vector<uint8_t> tohash; tohash.push_back(0x00); tohash.insert(tohash.end(), m.begin(), m.end());
    tagged_hash("TapSighash", tohash, out32);
}

// Assina P2TR (key-path). Requer amount/scriptPubKey da entrada e arrays de todos inputs (para sighash).
inline bool sign_input_p2tr_keypath(Transaction& tx, size_t in_idx, const uint8_t seckey32[32],
                                    const std::vector<uint64_t>& input_amounts,
                                    const std::vector<std::vector<uint8_t>>& input_scriptpubkeys,
                                    uint32_t sighash_type){
    using namespace bitcrypto;
    if (in_idx>=tx.vin.size()) return false;
    uint8_t h[32]; taproot_sighash_keypath(tx, in_idx, input_amounts, input_scriptpubkeys, sighash_type, h);
    // tweak a chave (sem script path -> merkle_root ausente)
    uint8_t sk_t[32]; if (!taproot_tweak_seckey(seckey32, nullptr, sk_t)) return false;
    // schnorr BIP340
    uint8_t sig64[64]; if (!bitcrypto::sign::schnorr_sign(sk_t, h, sig64)) return false;
    std::vector<uint8_t> sig(sig64, sig64+64);
    if ((sighash_type & 0xFF) != 0x00) sig.push_back((uint8_t)(sighash_type & 0xFF));
    // witness = [sig]
    tx.vin[in_idx].witness.clear();
    tx.vin[in_idx].witness.push_back(sig);
    tx.segwit = true; tx.set_segwit_if_any_witness();
    return true;
}

}} // ns
