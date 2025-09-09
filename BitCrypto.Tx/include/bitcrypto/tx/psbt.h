#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/encoding/base58.h>
#include <bitcrypto/encoding/b58check.h>
#include "tx.h"
#include "varint.h"

namespace bitcrypto { namespace tx { namespace psbt {

// Minimalista: PSBT v0 (BIP174) e PSBT v2 (BIP370) para casos simples (1-∞ entradas/saídas, single-sig).

inline void ser_compact_size(uint64_t v, std::vector<uint8_t>& out){ encode_varint(v, out); }
inline bool deser_compact_size(const uint8_t* p, size_t n, size_t& off, uint64_t& v){ return decode_varint(p, n, off, v); }

// --- PSBT v0 ---
struct PSBTV0 {
    Transaction unsigned_tx;
    struct In {
        bool has_witness_utxo=false;
        uint64_t value=0;
        std::vector<uint8_t> scriptPubKey;
        // partial sigs: pubkey(33) -> sig (DER+hashtype) para ECDSA; para Schnorr usar PSBT v2 (taproot)
        std::map<std::vector<uint8_t>, std::vector<uint8_t>> partial_sigs;
    };
    struct Out {
        // placeholder para campos comuns (não utilizados nesta entrega mínima)
        std::map<std::vector<uint8_t>, std::vector<uint8_t>> kv;
    };
    std::vector<In> ins;
    std::vector<Out> outs;

    std::vector<uint8_t> encode() const {
        std::vector<uint8_t> out;
        // magic
        const uint8_t magic[5] = {0x70,0x73,0x62,0x74,0xff}; out.insert(out.end(), magic, magic+5);
        // global: unsigned tx (key=0x00)
        out.push_back(0x01); out.push_back(0x00); // keylen=1, keytype=0x00
        std::vector<uint8_t> txser = unsigned_tx.serialize(true);
        ser_compact_size(txser.size(), out); out.insert(out.end(), txser.begin(), txser.end());
        out.push_back(0x00); // end of globals
        // inputs
        for (const auto& in : ins){
            if (in.has_witness_utxo){
                // key = 1 byte: 0x01 (PSBT_IN_WITNESS_UTXO)
                out.push_back(0x01); out.push_back(0x01);
                // value(8) + scriptsize + script
                std::vector<uint8_t> v; for (int j=0;j<8;j++) v.push_back((uint8_t)(in.value>>(8*j)));
                std::vector<uint8_t> val; val.insert(val.end(), v.begin(), v.end());
                encode_varint(in.scriptPubKey.size(), val); val.insert(val.end(), in.scriptPubKey.begin(), in.scriptPubKey.end());
                ser_compact_size(val.size(), out); out.insert(out.end(), val.begin(), val.end());
            }
            // partial sigs
            for (auto& kv : in.partial_sigs){
                std::vector<uint8_t> key; key.push_back(0x02); key.insert(key.end(), kv.first.begin(), kv.first.end()); // PSBT_IN_PARTIAL_SIG
                ser_compact_size(key.size(), out); out.insert(out.end(), key.begin(), key.end());
                ser_compact_size(kv.second.size(), out); out.insert(out.end(), kv.second.begin(), kv.second.end());
            }
            out.push_back(0x00); // end of input
        }
        // outputs
        for (const auto& o : outs){
            out.push_back(0x00); // end of output (vazio)
        }
        return out;
    }
};

// --- PSBT v2 (BIP370) minimalista para keypath schnorr ou ecdsa segwit ---
struct PSBTV2 {
    int32_t version=2;
    uint32_t locktime=0;
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    struct In {
        bool has_prevout=false;
        uint8_t txid[32]; uint32_t vout=0; uint64_t value=0; std::vector<uint8_t> scriptPubKey;
        std::vector<uint8_t> tap_key_sig; // schnorr 64B + sighash byte opcional
        std::vector<uint8_t> partial_sig; // ecdsa DER + sighash byte
    };
    std::vector<In> ins;

    std::vector<uint8_t> encode() const {
        std::vector<uint8_t> out;
        const uint8_t magic[5] = {0x70,0x73,0x62,0x74,0xff}; out.insert(out.end(), magic, magic+5);
        // Globals (key=PSBT_GLOBAL_TX_VERSION=0x02)
        out.push_back(0x01); out.push_back(0x02);
        std::vector<uint8_t> v; for (int i=0;i<4;i++) v.push_back((uint8_t)((uint32_t)version>>(8*i)));
        ser_compact_size(v.size(), out); out.insert(out.end(), v.begin(), v.end());
        // nInputs (0x0e) e nOutputs (0x0f)
        out.push_back(0x01); out.push_back(0x0e); std::vector<uint8_t> vi; encode_varint(vin.size(), vi); ser_compact_size(vi.size(), out); out.insert(out.end(), vi.begin(), vi.end());
        out.push_back(0x01); out.push_back(0x0f); std::vector<uint8_t> vo; encode_varint(vout.size(), vo); ser_compact_size(vo.size(), out); out.insert(out.end(), vo.begin(), vo.end());
        // locktime (0x03)
        out.push_back(0x01); out.push_back(0x03); std::vector<uint8_t> vl; for (int i=0;i<4;i++) vl.push_back((uint8_t)(locktime>>(8*i))); ser_compact_size(vl.size(), out); out.insert(out.end(), vl.begin(), vl.end());
        out.push_back(0x00); // end globals

        // Inputs
        for (size_t i=0;i<vin.size();i++){
            const auto& meta = ins[i];
            if (meta.has_prevout){
                std::vector<uint8_t> key; key.push_back(0x00); // PSBT_IN_PREVIOUS_TXID
                ser_compact_size(key.size(), out); out.insert(out.end(), key.begin(), key.end());
                ser_compact_size(32, out); out.insert(out.end(), meta.txid, meta.txid+32);
                std::vector<uint8_t> key2; key2.push_back(0x01); // PSBT_IN_OUTPUT_INDEX
                ser_compact_size(key2.size(), out); out.insert(out.end(), key2.begin(), key2.end());
                std::vector<uint8_t> vix; for (int j=0;j<4;j++) vix.push_back((uint8_t)(meta.vout>>(8*j))); ser_compact_size(vix.size(), out); out.insert(out.end(), vix.begin(), vix.end());
                // value + scriptPubKey (PSBT_IN_WITNESS_UTXO em v2 usa campos separados 0x18 e 0x19)
                std::vector<uint8_t> kval; kval.push_back(0x18); ser_compact_size(kval.size(), out); out.insert(out.end(), kval.begin(), kval.end());
                std::vector<uint8_t> val; for (int j=0;j<8;j++) val.push_back((uint8_t)(meta.value>>(8*j))); ser_compact_size(val.size(), out); out.insert(out.end(), val.begin(), val.end());
                std::vector<uint8_t> kspk; kspk.push_back(0x19); ser_compact_size(kspk.size(), out); out.insert(out.end(), kspk.begin(), kspk.end());
                std::vector<uint8_t> spk=meta.scriptPubKey; ser_compact_size(spk.size(), out); out.insert(out.end(), spk.begin(), spk.end());
            }
            if (!meta.tap_key_sig.empty()){
                std::vector<uint8_t> key; key.push_back(0x1d); // PSBT_IN_TAP_KEY_SIG
                ser_compact_size(key.size(), out); out.insert(out.end(), key.begin(), key.end());
                ser_compact_size(meta.tap_key_sig.size(), out); out.insert(out.end(), meta.tap_key_sig.begin(), meta.tap_key_sig.end());
            }
            if (!meta.partial_sig.empty()){
                std::vector<uint8_t> key; key.push_back(0x13); // PSBT_IN_PARTIAL_SIG (v2)
                ser_compact_size(key.size(), out); out.insert(out.end(), key.begin(), key.end());
                ser_compact_size(meta.partial_sig.size(), out); out.insert(out.end(), meta.partial_sig.begin(), meta.partial_sig.end());
            }
            out.push_back(0x00);
        }
        // Outputs (v2 requer scriptPubKey/amount nos próprios outputs globais em separado; omitimos metadados aqui)
        for (size_t i=0;i<vout.size();i++){
            out.push_back(0x00);
        }
        return out;
    }
};

}}} // ns
