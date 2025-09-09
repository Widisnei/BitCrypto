#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include "tx.h"

namespace bitcrypto { namespace tx {

enum : uint32_t { SIGHASH_ALL = 0x01 };

// scriptCode para P2WPKH (BIP-143) a partir de hash160(pubkey)
inline std::vector<uint8_t> scriptCode_p2wpkh(const uint8_t h160[20]){
    std::vector<uint8_t> sc; sc.reserve(1+1+20+2);
    sc.push_back(0x19); // tamanho = 25
    sc.push_back(0x76); // OP_DUP
    sc.push_back(0xA9); // OP_HASH160
    sc.push_back(0x14); // push(20)
    sc.insert(sc.end(), h160, h160+20);
    sc.push_back(0x88); // OP_EQUALVERIFY
    sc.push_back(0xAC); // OP_CHECKSIG
    return sc;
}

// Sighash legado (SIGHASH_ALL) — NÃO usa amount
inline void sighash_legacy_all(const Tx& tx, size_t in_index, const std::vector<uint8_t>& scriptCode, uint32_t sighash_type, uint8_t out32[32]){
    std::vector<uint8_t> ser;
    write_u32(ser, tx.version);
    write_varint(ser, tx.vin.size());
    for (size_t i=0;i<tx.vin.size();++i){
        auto& in = tx.vin[i];
        ser.insert(ser.end(), in.prevout.txid, in.prevout.txid+32);
        write_u32(ser, in.prevout.vout);
        if (i==in_index){ write_varint(ser, scriptCode.size()); write_bytes(ser, scriptCode); }
        else { write_varint(ser, 0); }
        write_u32(ser, in.sequence);
    }
    write_varint(ser, tx.vout.size());
    for (auto& o : tx.vout){
        write_u64(ser, o.value);
        write_varint(ser, o.scriptPubKey.size());
        write_bytes(ser, o.scriptPubKey);
    }
    write_u32(ser, tx.locktime);
    write_u32(ser, sighash_type);
    hash256(ser, out32);
}

// Sighash BIP-143 (SegWit v0) — SIGHASH_ALL, scriptCode e amount são obrigatórios
inline void sighash_segwit_v0_all(const Tx& tx, size_t in_index, const std::vector<uint8_t>& scriptCode, uint64_t amount_sat, uint8_t out32[32]){
    using namespace bitcrypto::hash;
    std::vector<uint8_t> buf;
    // hashPrevouts
    std::vector<uint8_t> hpv; for (auto& in : tx.vin){ hpv.insert(hpv.end(), in.prevout.txid, in.prevout.txid+32); write_u32(hpv, in.prevout.vout); }
    uint8_t Hprev[32]; hash256(hpv, Hprev);
    // hashSequence
    std::vector<uint8_t> hsq; for (auto& in : tx.vin){ write_u32(hsq, in.sequence); }
    uint8_t Hseq[32]; hash256(hsq, Hseq);
    // hashOutputs
    std::vector<uint8_t> hout; for (auto& o : tx.vout){ write_u64(hout, o.value); write_varint(hout, o.scriptPubKey.size()); write_bytes(hout, o.scriptPubKey); }
    uint8_t Hout[32]; hash256(hout, Hout);

    write_u32(buf, tx.version);
    buf.insert(buf.end(), Hprev, Hprev+32);
    buf.insert(buf.end(), Hseq, Hseq+32);
    // outpoint atual
    auto& in = tx.vin[in_index];
    buf.insert(buf.end(), in.prevout.txid, in.prevout.txid+32);
    write_u32(buf, in.prevout.vout);
    // scriptCode
    write_varint(buf, scriptCode.size());
    write_bytes(buf, scriptCode);
    // amount
    write_u64(buf, amount_sat);
    // sequence
    write_u32(buf, in.sequence);
    // outputs
    buf.insert(buf.end(), Hout, Hout+32);
    // locktime
    write_u32(buf, tx.locktime);
    // sighash type
    write_u32(buf, SIGHASH_ALL);
    hash256(buf, out32);
}

}} // ns
