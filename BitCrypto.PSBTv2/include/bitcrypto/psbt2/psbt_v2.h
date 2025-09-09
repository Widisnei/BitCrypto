using UnknownKV = std::pair<std::vector<uint8_t>, std::vector<uint8_t>>; // unknown_in_kv
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <utility>
#include <bitcrypto/encoding/varint.h>
#include <bitcrypto/encoding/base64.h>
#include <bitcrypto/tx/tx.h>
#include <bitcrypto/psbt/psbt.h>

namespace bitcrypto { namespace psbt2 {

struct In {
    uint8_t prev_txid[32]; uint32_t vout=0; uint32_t sequence=0xFFFFFFFF;
    bool has_witness_utxo=false; bitcrypto::tx::TxOut witness_utxo;
    bool has_non_witness_utxo=false; bitcrypto::tx::Transaction non_witness_utxo;
    // partial signatures (pub, sig)
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> partial_sigs;

    std::vector<UnknownKV> unknown_kv; // unknown_in_kv
};

struct Out { uint64_t amount=0; std::vector<uint8_t> script; 
    std::vector<UnknownKV> unknown_kv; // unknown_in_kv
};

struct PSBT2 {
    uint32_t tx_locktime=0;
    int32_t tx_version=2;
    std::vector<In> ins; std::vector<Out> outs;

    // ---- Serializer (Creator/Constructor) ----
    std::vector<uint8_t> serialize() const{
        using namespace bitcrypto::encoding;
        std::vector<uint8_t> out;
        const uint8_t magic[5]={0x70,0x73,0x62,0x74,0xff
    std::vector<UnknownKV> unknown_globals; // unknown_in_kv
}; out.insert(out.end(), magic, magic+5);
        // PSBT_GLOBAL_VERSION (0xFB) = 2
        out.push_back(0x01); out.push_back(0xFB); out.push_back(0x01); out.push_back(0x02);
        // PSBT_GLOBAL_TX_VERSION (0x02)
        out.push_back(0x01); out.push_back(0x02); std::vector<uint8_t> v; for(int i=0;i<4;i++) v.push_back((uint8_t)((tx_version>>(8*i))&0xFF)); write_varint(out, v.size()); out.insert(out.end(), v.begin(), v.end());
        // PSBT_GLOBAL_TX_LOCKTIME (0x03)
        out.push_back(0x01); out.push_back(0x03);
        { std::vector<uint8_t> vlt; for(int i=0;i<4;i++) vlt.push_back((uint8_t)((tx_locktime>>(8*i))&0xFF)); write_varint(out, vlt.size()); out.insert(out.end(), vlt.begin(), vlt.end()); }
        // INPUT_COUNT (0x04)
        out.push_back(0x01); out.push_back(0x04); std::vector<uint8_t> vi; write_varint(vi, ins.size()); write_varint(out, vi.size()); out.insert(out.end(), vi.begin(), vi.end());
        // OUTPUT_COUNT (0x05)
        out.push_back(0x01); out.push_back(0x05); std::vector<uint8_t> vo; write_varint(vo, outs.size()); write_varint(out, vo.size()); out.insert(out.end(), vo.begin(), vo.end());
        out.push_back(0x00);
        // inputs
        for (const auto& i : ins){
            // PREVIOUS_TXID (0x0e)
            out.push_back(0x01); out.push_back(0x0e); write_varint(out, 32); out.insert(out.end(), i.prev_txid, i.prev_txid+32);
            // OUTPUT_INDEX (0x0f)
            out.push_back(0x01); out.push_back(0x0f); std::vector<uint8_t> idx; for(int k=0;k<4;k++) idx.push_back((uint8_t)((i.vout>>(8*k))&0xFF)); write_varint(out, idx.size()); out.insert(out.end(), idx.begin(), idx.end());
            // SEQUENCE (0x10)
            out.push_back(0x01); out.push_back(0x10); std::vector<uint8_t> seq; for(int k=0;k<4;k++) seq.push_back((uint8_t)((i.sequence>>(8*k))&0xFF)); write_varint(out, seq.size()); out.insert(out.end(), seq.begin(), seq.end());
            // witness_utxo (reuse 0x01 encoding from v0)
            if (i.has_witness_utxo){
                out.push_back(0x01); out.push_back(0x01);
                std::vector<uint8_t> buf; for(int k=0;k<8;k++) buf.push_back((uint8_t)((i.witness_utxo.value>>(8*k))&0xFF));
                write_varint(buf, i.witness_utxo.scriptPubKey.size());
                buf.insert(buf.end(), i.witness_utxo.scriptPubKey.begin(), i.witness_utxo.scriptPubKey.end());
                write_varint(out, buf.size()); out.insert(out.end(), buf.begin(), buf.end());
            }
            // partial_sigs (0x02 + 33B pubkey)
            for (const auto& kv : i.partial_sigs){
                std::vector<uint8_t> key; key.push_back(0x02); key.insert(key.end(), kv.first.begin(), kv.first.end());
                write_varint(out, key.size()); out.insert(out.end(), key.begin(), key.end());
                write_varint(out, kv.second.size()); out.insert(out.end(), kv.second.begin(), kv.second.end());
            }
            out.push_back(0x00);
        }
        // outputs
        for (const auto& o : outs){
            // AMOUNT (0x03)
            out.push_back(0x01); out.push_back(0x03); std::vector<uint8_t> a; for(int k=0;k<8;k++) a.push_back((uint8_t)((o.amount>>(8*k))&0xFF)); write_varint(out, a.size()); out.insert(out.end(), a.begin(), a.end());
            // SCRIPT (0x04)
            out.push_back(0x01); out.push_back(0x04); std::vector<uint8_t> s; write_varint(s, o.script.size()); s.insert(s.end(), o.script.begin(), o.script.end()); write_varint(out, s.size()); out.insert(out.end(), s.begin(), s.end());
            out.push_back(0x00);
        }
        return out;
    }
    std::string to_base64() const{ auto raw=serialize(); return bitcrypto::encoding::base64_encode(raw); }

    // ---- Parser (subset dos campos que emitimos) ----
    static bool parse(const std::vector<uint8_t>& raw, PSBT2& out){
        using namespace bitcrypto::encoding;
        size_t off=0; if (raw.size()<5) return false;
        if (!(raw[0]==0x70&&raw[1]==0x73&&raw[2]==0x62&&raw[3]==0x74&&raw[4]==0xff)) return false; off=5;
        uint64_t klen=0,vlen=0;
        auto read_vi=[&](uint64_t& v)->bool{ if(off>=raw.size()) return false; uint8_t ch=raw[off++]; if(ch<0xFD){ v=ch; return true; } if(ch==0xFD){ if(off+2>raw.size()) return false; v=raw[off]|(uint64_t)raw[off+1]<<8; off+=2; return true; } if(ch==0xFE){ if(off+4>raw.size()) return false; v=0; for(int i=0;i<4;i++) v|=(uint64_t)raw[off+i]<<(8*i); off+=4; return true; } if(ch==0xFF){ if(off+8>raw.size()) return false; v=0; for(int i=0;i<8;i++) v|=(uint64_t)raw[off+i]<<(8*i); off+=8; return true; } return false; };
        // globals
        while (true){
            if (off>=raw.size()) return false;
            if (raw[off]==0x00){ off++; break; }
            if (!read_vi(klen) || off+klen>raw.size()) return false; const uint8_t* k=&raw[off]; off+=klen;
            if (!read_vi(vlen) || off+vlen>raw.size()) return false; const uint8_t* v=&raw[off]; off+=vlen;
            if (klen==1 && k[0]==0xFB){ if (!(vlen==1 && v[0]==0x02)) return false; }
            else if (klen==1 && k[0]==0x02){ if (vlen!=4) return false; out.tx_version = (int32_t)(v[0] | (v[1]<<8) | (v[2]<<16) | (v[3]<<24)); }
            else if (klen==1 && k[0]==0x04){ uint64_t n; size_t o=0; if(!read_varint(v,vlen,o,n)) return false; out.ins.resize((size_t)n); }
            else if (klen==1 && k[0]==0x05){ uint64_t n; size_t o=0; if(!read_varint(v,vlen,o,n)) return false; out.outs.resize((size_t)n); }
            else { /* ignore unknown */ }
        }
        // inputs
        for (size_t i=0;i<out.ins.size(); ++i){
            while (true){
                if (off>=raw.size()) return false;
                if (raw[off]==0x00){ off++; break; }
                if (!read_vi(klen) || off+klen>raw.size()) return false; const uint8_t* k=&raw[off]; off+=klen;
                if (!read_vi(vlen) || off+vlen>raw.size()) return false; const uint8_t* v=&raw[off]; off+=vlen;
                if (klen==1 && k[0]==0x0e){ if (vlen!=32) return false; std::memcpy(out.ins[i].prev_txid, v, 32); }
                else if (klen==1 && k[0]==0x0f){ if (vlen!=4) return false; out.ins[i].vout = (uint32_t)(v[0] | (v[1]<<8) | (v[2]<<16) | (v[3]<<24)); }
                else if (klen==1 && k[0]==0x10){ if (vlen!=4) return false; out.ins[i].sequence = (uint32_t)(v[0] | (v[1]<<8) | (v[2]<<16) | (v[3]<<24)); }
                else if (klen==1 && k[0]==0x01){
                    // witness_utxo
                    size_t o=0; if (vlen<8) return false; uint64_t val=0; for(int j=0;j<8;j++) val |= (uint64_t)v[o+j]<<(8*j); o+=8;
                    uint64_t sl; if(!read_varint(v,vlen,o,sl)) return false; if (o+sl>vlen) return false;
                    out.ins[i].has_witness_utxo=true; out.ins[i].witness_utxo.value=val; out.ins[i].witness_utxo.scriptPubKey.assign(v+o, v+o+sl);
                } else if (klen==34 && k[0]==0x02){
                    // partial sig
                    out.ins[i].partial_sigs.emplace_back(std::vector<uint8_t>(k+1,k+34), std::vector<uint8_t>(v,v+vlen));
                } else {
                    // ignore
                }
            }
        }
        // outputs
        for (size_t i=0;i<out.outs.size(); ++i){
            while (true){
                if (off>=raw.size()) return false;
                if (raw[off]==0x00){ off++; break; }
                if (!read_vi(klen) || off+klen>raw.size()) return false; const uint8_t* k=&raw[off]; off+=klen;
                if (!read_vi(vlen) || off+vlen>raw.size()) return false; const uint8_t* v=&raw[off]; off+=vlen;
                if (klen==1 && k[0]==0x03){ if (vlen!=8) return false; uint64_t val=0; for(int j=0;j<8;j++) val |= (uint64_t)v[j]<<(8*j); out.outs[i].amount=val; }
                else if (klen==1 && k[0]==0x04){
                    size_t o=0; uint64_t sl; if(!read_varint(v,vlen,o,sl)) return false; if (o+sl>vlen) return false;
                    out.outs[i].script.assign(v+o, v+o+sl);
                } else { /* ignore */ }
            }
        }
        return true;
    }

    static bool from_base64(const std::string& b64, PSBT2& out){ std::vector<uint8_t> raw; if (!bitcrypto::encoding::base64_decode(b64, raw)) return false; return parse(raw, out); }

    // ---- Conversão para PSBT v0 (para reusar signer robusto e extrair TX com witnesses) ----
    bool to_psbt_v0(bitcrypto::psbt::PSBT& p0) const {
        p0.unsigned_tx.version = tx_version; p0.unsigned_tx.locktime=0; p0.unsigned_tx.vin.clear(); p0.unsigned_tx.vout.clear();
        p0.inputs.clear(); p0.outputs.clear();
        // vin/vout
        for (const auto& i : ins){
            bitcrypto::tx::TxIn in; std::memcpy(in.prevout.txid, i.prev_txid, 32); in.prevout.vout=i.vout; in.sequence=i.sequence;
            p0.unsigned_tx.vin.push_back(in);
        }
        for (const auto& o : outs){
            bitcrypto::tx::TxOut to; to.value=o.amount; to.scriptPubKey=o.script; p0.unsigned_tx.vout.push_back(to);
        }
        // maps
        p0.inputs.resize(ins.size()); p0.outputs.resize(outs.size());
        for (size_t i=0;i<ins.size(); ++i){
            if (ins[i].has_witness_utxo){
                p0.inputs[i].has_witness_utxo=true; p0.inputs[i].witness_utxo=ins[i].witness_utxo; p0.inputs[i].sighash_type=bitcrypto::tx::SIGHASH_ALL;
            } else if (ins[i].has_non_witness_utxo){
                p0.inputs[i].has_non_witness_utxo=true; p0.inputs[i].sighash_type=bitcrypto::tx::SIGHASH_ALL;
            } else {
                // não suportado
                return false;
            }
        }
        return true;
    }
};

}} // ns
