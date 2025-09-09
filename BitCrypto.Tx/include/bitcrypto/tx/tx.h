#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <bitcrypto/hash/sha256.h>

namespace bitcrypto { namespace tx {

// Varint (Bitcoin) — apenas encode/serialize
inline void write_varint(std::vector<uint8_t>& out, uint64_t v){
    if (v < 0xFD){ out.push_back((uint8_t)v); return; }
    else if (v <= 0xFFFF){ out.push_back(0xFD); out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v>>8)&0xFF)); }
    else if (v <= 0xFFFFFFFFULL){ out.push_back(0xFE);
        for (int i=0;i<4;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF));
    } else {
        out.push_back(0xFF); for (int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF));
    }
}

inline void write_u32(std::vector<uint8_t>& out, uint32_t v){ for (int i=0;i<4;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF)); }
inline void write_u64(std::vector<uint8_t>& out, uint64_t v){ for (int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF)); }
inline void write_bytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& v){ out.insert(out.end(), v.begin(), v.end()); }

struct OutPoint { uint8_t txid[32]; uint32_t vout; };
struct TxIn { OutPoint prevout; std::vector<uint8_t> scriptSig; uint32_t sequence; std::vector<std::vector<uint8_t>> witness; };
struct TxOut { uint64_t value; std::vector<uint8_t> scriptPubKey; };

struct Tx {
    uint32_t version{2};
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    uint32_t locktime{0};
    bool has_witness{false}; // controle para serialização segwit/wtxid

    // Marca como segwit se qualquer entrada possuir witness
    inline void set_segwit_if_any_witness(){
        has_witness = false;
        for (const auto& in : vin){
            if (!in.witness.empty()){ has_witness = true; break; }
        }
    }
};

// Alias legado para compatibilidade com código existente
using Transaction = Tx;

inline void serialize_legacy(const Tx& tx, std::vector<uint8_t>& out){
    write_u32(out, tx.version);
    write_varint(out, tx.vin.size());
    for (auto& in : tx.vin){
        // txid little-endian na serialização (txid é bswap(hash))
        out.insert(out.end(), in.prevout.txid, in.prevout.txid+32);
        write_u32(out, in.prevout.vout);
        write_varint(out, in.scriptSig.size());
        write_bytes(out, in.scriptSig);
        write_u32(out, in.sequence);
    }
    write_varint(out, tx.vout.size());
    for (auto& o : tx.vout){
        write_u64(out, o.value);
        write_varint(out, o.scriptPubKey.size());
        write_bytes(out, o.scriptPubKey);
    }
    write_u32(out, tx.locktime);
}

inline void serialize_segwit(const Tx& tx, std::vector<uint8_t>& out){
    write_u32(out, tx.version);
    out.push_back(0x00); out.push_back(0x01); // marker+flag
    write_varint(out, tx.vin.size());
    for (auto& in : tx.vin){
        out.insert(out.end(), in.prevout.txid, in.prevout.txid+32);
        write_u32(out, in.prevout.vout);
        write_varint(out, in.scriptSig.size());
        write_bytes(out, in.scriptSig);
        write_u32(out, in.sequence);
    }
    write_varint(out, tx.vout.size());
    for (auto& o : tx.vout){
        write_u64(out, o.value);
        write_varint(out, o.scriptPubKey.size());
        write_bytes(out, o.scriptPubKey);
    }
    // witnesses
    for (auto& in : tx.vin){
        write_varint(out, in.witness.size());
        for (auto& w : in.witness){ write_varint(out, w.size()); write_bytes(out, w); }
    }
    write_u32(out, tx.locktime);
}

// txid = double-SHA256(legacy serialization)
inline void hash256(const std::vector<uint8_t>& data, uint8_t out32[32]){
    using namespace bitcrypto::hash;
    uint8_t h1[32]; sha256(data.data(), data.size(), h1); sha256(h1, 32, out32);
}
inline void txid(const Tx& tx, uint8_t out32[32]){
    std::vector<uint8_t> ser; serialize_legacy(tx, ser); hash256(ser, out32);
}
inline void wtxid(const Tx& tx, uint8_t out32[32]){
    if (!tx.has_witness){ txid(tx,out32); return; }
    std::vector<uint8_t> ser; serialize_segwit(tx, ser); hash256(ser, out32);
}

}} // ns
