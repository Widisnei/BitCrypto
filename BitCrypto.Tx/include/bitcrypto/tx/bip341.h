#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include "tx.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/sha256.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/tagged.h"
#include "../../BitCrypto.Encoding/include/bitcrypto/encoding/varint.h"

namespace bitcrypto { namespace tx {

inline void ser_outpoint(std::vector<uint8_t>& o, const OutPoint& op){
    o.insert(o.end(), op.txid, op.txid+32);
    for (int i=0;i<4;i++) o.push_back((uint8_t)((op.vout>>(8*i))&0xFF));
}
inline void ser_sequence(std::vector<uint8_t>& o, uint32_t seq){
    for (int i=0;i<4;i++) o.push_back((uint8_t)((seq>>(8*i))&0xFF));
}
inline void ser_amount(std::vector<uint8_t>& o, uint64_t v){
    for (int i=0;i<8;i++) o.push_back((uint8_t)((v>>(8*i))&0xFF));
}
inline void ser_script(std::vector<uint8_t>& o, const std::vector<uint8_t>& scr){
    bitcrypto::encoding::write_varint(o, scr.size());
    o.insert(o.end(), scr.begin(), scr.end());
}
inline void ser_output(std::vector<uint8_t>& o, const TxOut& txo){
    ser_amount(o, txo.value);
    ser_script(o, txo.scriptPubKey);
}

inline void bip341_sighash_keypath(const Transaction& tx, size_t in_idx,
                                   const std::vector<uint64_t>& amounts,
                                   const std::vector<std::vector<uint8_t>>& scriptPubKeys,
                                   uint32_t sighash, uint8_t out[32]){
    using namespace bitcrypto::hash;
    using namespace bitcrypto::encoding;
    if (tx.vin.size()!=amounts.size() || tx.vin.size()!=scriptPubKeys.size()){ std::memset(out,0,32); return; }
    uint8_t sha_prevouts[32], sha_amounts[32], sha_scriptpubkeys[32], sha_sequences[32], sha_outputs[32];
    if (sighash & SIGHASH_ANYONECANPAY){ std::memset(sha_prevouts,0,32); }
    else {
        std::vector<uint8_t> buf;
        for (const auto& in : tx.vin){ ser_outpoint(buf, in.prevout); }
        sha256(buf.data(), buf.size(), sha_prevouts);
    }
    if (sighash & SIGHASH_ANYONECANPAY){ std::memset(sha_amounts,0,32); }
    else {
        std::vector<uint8_t> buf; for (auto a: amounts) ser_amount(buf, a);
        sha256(buf.data(), buf.size(), sha_amounts);
    }
    if (sighash & SIGHASH_ANYONECANPAY){ std::memset(sha_scriptpubkeys,0,32); }
    else {
        std::vector<uint8_t> buf;
        for (const auto& s : scriptPubKeys){ ser_script(buf, s); }
        sha256(buf.data(), buf.size(), sha_scriptpubkeys);
    }
    if ((sighash & SIGHASH_ANYONECANPAY) || ((sighash & 3)==SIGHASH_SINGLE) || ((sighash & 3)==SIGHASH_NONE)){
        std::memset(sha_sequences,0,32);
    } else {
        std::vector<uint8_t> buf; for (const auto& in: tx.vin) ser_sequence(buf, in.sequence);
        sha256(buf.data(), buf.size(), sha_sequences);
    }
    if ((sighash & 3)==SIGHASH_ALL){
        std::vector<uint8_t> buf; for (const auto& o: tx.vout) ser_output(buf, o);
        sha256(buf.data(), buf.size(), sha_outputs);
    } else if ((sighash & 3)==SIGHASH_SINGLE && in_idx<tx.vout.size()){
        std::vector<uint8_t> buf; ser_output(buf, tx.vout[in_idx]); sha256(buf.data(), buf.size(), sha_outputs);
    } else { std::memset(sha_outputs,0,32); }

    std::vector<uint8_t> m;
    m.push_back((uint8_t)(sighash & 0xFF));
    for(int i=0;i<4;i++) m.push_back((uint8_t)((tx.version>>(8*i))&0xFF));
    for(int i=0;i<4;i++) m.push_back((uint8_t)((tx.locktime>>(8*i))&0xFF));
    if (!(sighash & SIGHASH_ANYONECANPAY)){
        m.insert(m.end(), sha_prevouts, sha_prevouts+32);
        m.insert(m.end(), sha_amounts, sha_amounts+32);
        m.insert(m.end(), sha_scriptpubkeys, sha_scriptpubkeys+32);
        m.insert(m.end(), sha_sequences, sha_sequences+32);
    }
    if (((sighash & 3)!=SIGHASH_NONE) && ((sighash & 3)!=SIGHASH_SINGLE)){
        m.insert(m.end(), sha_outputs, sha_outputs+32);
    }
    uint8_t spend_type = 0; m.push_back(spend_type);
    if (sighash & SIGHASH_ANYONECANPAY){
        const auto& in = tx.vin[in_idx];
        ser_outpoint(m, in.prevout);
        ser_amount(m, amounts[in_idx]);
        ser_script(m, scriptPubKeys[in_idx]);
        ser_sequence(m, in.sequence);
    } else {
        for (int i=0;i<4;i++) m.push_back((uint8_t)((in_idx>>(8*i))&0xFF));
    }
    std::vector<uint8_t> pref; pref.push_back(0x00); pref.insert(pref.end(), m.begin(), m.end());
    tagged_sha256("TapSighash", pref.data(), pref.size(), out);
}

}} // ns
