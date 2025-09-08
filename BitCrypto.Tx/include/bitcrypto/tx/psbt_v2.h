using UnknownKV = std::pair<std::vector<uint8_t>, std::vector<uint8_t>>; // unknown_in_kv
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <utility>
#include "../../BitCrypto.Encoding/include/bitcrypto/encoding/varint.h"
#include "../../BitCrypto.Encoding/include/bitcrypto/encoding/base64.h"
#include "tx.h"
#include "sign.h"
#include "taproot.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/hash160.h"

namespace bitcrypto { namespace psbt2 {

struct In {
    uint8_t prev_txid[32]; uint32_t vout=0; uint32_t sequence=0xFFFFFFFF;
    bool has_witness_utxo=false; bitcrypto::tx::TxOut witness_utxo;
    bool has_non_witness_utxo=false; bitcrypto::tx::Transaction non_witness_utxo;
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> partial_sigs;
    std::vector<uint8_t> tap_key_sig;
    uint32_t sighash_type = bitcrypto::tx::SIGHASH_ALL;

    std::vector<UnknownKV> unknown_kv; // unknown_in_kv
};

struct Out { uint64_t amount=0; std::vector<uint8_t> script; 
    std::vector<UnknownKV> unknown_kv; // unknown_in_kv
};

struct PSBT2 {
    int32_t tx_version=2;
    std::vector<In> ins; std::vector<Out> outs;

    std::vector<uint8_t> serialize() const{
        using namespace bitcrypto::encoding;
        std::vector<uint8_t> out;
        const uint8_t magic[5]={0x70,0x73,0x62,0x74,0xff
    std::vector<UnknownKV> unknown_globals; // unknown_in_kv
}; out.insert(out.end(), magic, magic+5);
        // PSBT_GLOBAL_VERSION (0xFB) = 2
        out.push_back(0x01); out.push_back(0xFB); out.push_back(0x01); out.push_back(0x02);
        // PSBT_GLOBAL_TX_VERSION (0x02)
        out.push_back(0x01); out.push_back(0x02);
        std::vector<uint8_t> v; for(int i=0;i<4;i++) v.push_back((uint8_t)((tx_version>>(8*i))&0xFF));
        write_varint(out, v.size()); out.insert(out.end(), v.begin(), v.end());
        // INPUT_COUNT (0x04)
        out.push_back(0x01); out.push_back(0x04);
        std::vector<uint8_t> vi; write_varint(vi, ins.size()); write_varint(out, vi.size()); out.insert(out.end(), vi.begin(), vi.end());
        // OUTPUT_COUNT (0x05)
        out.push_back(0x01); out.push_back(0x05);
        std::vector<uint8_t> vo; write_varint(vo, outs.size()); write_varint(out, vo.size()); out.insert(out.end(), vo.begin(), vo.end());
        out.push_back(0x00);
        // inputs
        for (const auto& i : ins){
            out.push_back(0x01); out.push_back(0x0e); write_varint(out, 32); out.insert(out.end(), i.prev_txid, i.prev_txid+32);
            out.push_back(0x01); out.push_back(0x0f); std::vector<uint8_t> x; for(int k=0;k<4;k++) x.push_back((uint8_t)((i.vout>>(8*k))&0xFF)); write_varint(out, x.size()); out.insert(out.end(), x.begin(), x.end());
            out.push_back(0x01); out.push_back(0x10); std::vector<uint8_t> y; for(int k=0;k<4;k++) y.push_back((uint8_t)((i.sequence>>(8*k))&0xFF)); write_varint(out, y.size()); out.insert(out.end(), y.begin(), y.end());
            if (i.sighash_type){ out.push_back(0x01); out.push_back(0x0c); std::vector<uint8_t> sh; for(int k=0;k<4;k++) sh.push_back((uint8_t)((i.sighash_type>>(8*k))&0xFF)); write_varint(out, sh.size()); out.insert(out.end(), sh.begin(), sh.end()); }
            if (i.has_witness_utxo){
                out.push_back(0x01); out.push_back(0x01);
                std::vector<uint8_t> buf; for (int k=0;k<8;k++) buf.push_back((uint8_t)((i.witness_utxo.value>>(8*k))&0xFF));
                write_varint(buf, i.witness_utxo.scriptPubKey.size()); buf.insert(buf.end(), i.witness_utxo.scriptPubKey.begin(), i.witness_utxo.scriptPubKey.end());
                write_varint(out, buf.size()); out.insert(out.end(), buf.begin(), buf.end());
            }
            if (i.has_non_witness_utxo){
                out.push_back(0x01); out.push_back(0x00);
                auto raw = i.non_witness_utxo.serialize(false); write_varint(out, raw.size()); out.insert(out.end(), raw.begin(), raw.end());
            }
            for (const auto& kv : i.partial_sigs){
                std::vector<uint8_t> key; key.push_back(0x02); key.insert(key.end(), kv.first.begin(), kv.first.end());
                write_varint(out, key.size()); out.insert(out.end(), key.begin(), key.end());
                write_varint(out, kv.second.size()); out.insert(out.end(), kv.second.begin(), kv.second.end());
            }
            if (!i.tap_key_sig.empty()){
                out.push_back(0x01); out.push_back(0x13);
                write_varint(out, i.tap_key_sig.size()); out.insert(out.end(), i.tap_key_sig.begin(), i.tap_key_sig.end());
            }
            out.push_back(0x00);
        }
        // outputs
        for (const auto& o : outs){
            out.push_back(0x01); out.push_back(0x03); std::vector<uint8_t> a; for (int k=0;k<8;k++) a.push_back((uint8_t)((o.amount>>(8*k))&0xFF)); write_varint(out, a.size()); out.insert(out.end(), a.begin(), a.end());
            out.push_back(0x01); out.push_back(0x04); std::vector<uint8_t> s; write_varint(s, o.script.size()); s.insert(s.end(), o.script.begin(), o.script.end()); write_varint(out, s.size()); out.insert(out.end(), s.begin(), s.end());
            out.push_back(0x00);
        }
        return out;
    }

    std::string to_base64() const{ auto raw=serialize(); return bitcrypto::encoding::base64_encode(raw); }

    static bool parse(const std::vector<uint8_t>& raw, PSBT2& out){
        using namespace bitcrypto::encoding;
        size_t off=0; if (raw.size()<5) return false;
        if (!(raw[0]==0x70&&raw[1]==0x73&&raw[2]==0x62&&raw[3]==0x74&&raw[4]==0xff)) return false; off=5;
        out = PSBT2{};
        // Global map
        while (true){
            if (off>=raw.size()) return false;
            if (raw[off]==0x00){ off++; break; }
            uint64_t klen; if(!read_varint(raw.data(), raw.size(), off, klen)) return false;
            if (off+klen>raw.size()) return false; const uint8_t* k=&raw[off]; off+=klen;
            uint64_t vlen; if(!read_varint(raw.data(), raw.size(), off, vlen)) return false;
            if (off+vlen>raw.size()) return false; const uint8_t* v=&raw[off]; off+=vlen;
            if (klen==1 && k[0]==0xFB){
                if (!(vlen==1 && v[0]==0x02)) return false;
            } else if (klen==1 && k[0]==0x02){
                if (vlen!=4) return false; out.tx_version = (int32_t)(v[0]|(v[1]<<8)|(v[2]<<16)|(v[3]<<24));
            } else {
                // ignore other globals
            }
        }
        // Input maps
        std::vector<In> ins; ins.clear(); ins.push_back(In{});
        auto have_any=false;
        while (off < raw.size()){
            if (raw[off]==0x00){ // end of current input map
                off++; if (have_any){ ins.push_back(In{}); have_any=false; } else { break; }
                continue;
            }
            uint64_t klen; if(!read_varint(raw.data(), raw.size(), off, klen)) return false;
            if (off+klen>raw.size()) return false; const uint8_t* k=&raw[off]; off+=klen;
            uint64_t vlen; if(!read_varint(raw.data(), raw.size(), off, vlen)) return false;
            if (off+vlen>raw.size()) return false; const uint8_t* v=&raw[off]; off+=vlen;
            In& I = ins.back(); have_any=true;
            if (klen==1 && k[0]==0x0e){ if (vlen!=32) return false; std::memcpy(I.prev_txid, v, 32); }
            else if (klen==1 && k[0]==0x0f){ if (vlen!=4) return false; I.vout=(uint32_t)(v[0]|(v[1]<<8)|(v[2]<<16)|(v[3]<<24)); }
            else if (klen==1 && k[0]==0x10){ if (vlen!=4) return false; I.sequence=(uint32_t)(v[0]|(v[1]<<8)|(v[2]<<16)|(v[3]<<24)); }
            else if (klen==1 && k[0]==0x0c){ if (vlen!=4) return false; I.sighash_type=(uint32_t)(v[0]|(v[1]<<8)|(v[2]<<16)|(v[3]<<24)); }
            else if (klen==1 && k[0]==0x01){
                size_t o=0; if (vlen<8) return false; uint64_t val=0; for(int i=0;i<8;i++) val|=(uint64_t)v[i]<<(8*i); o+=8;
                uint64_t sl; if(!read_varint(v, vlen, o, sl)) return false; if (o+sl>vlen) return false;
                I.has_witness_utxo=true; I.witness_utxo.value=val; I.witness_utxo.scriptPubKey.assign(v+o, v+o+sl);
            } else if (klen==1 && k[0]==0x00){
                I.has_non_witness_utxo=true;
            } else if (klen==34 && k[0]==0x02){
                I.partial_sigs.emplace_back(std::vector<uint8_t>(k+1,k+34), std::vector<uint8_t>(v,v+vlen));
            } else if (klen==1 && k[0]==0x13){
                I.tap_key_sig.assign(v, v+vlen);
            } else {
                // ignore
            }
        }
        if (!ins.empty() && !have_any) ins.pop_back();
        out.ins = ins;

        // Output maps
        std::vector<Out> outs; outs.clear();
        while (off<raw.size()){
            if (raw[off]==0x00){ off++; if (!outs.empty()) outs.push_back(Out{}); continue; }
            uint64_t klen; if(!read_varint(raw.data(), raw.size(), off, klen)) break;
            if (off+klen>raw.size()) break; const uint8_t* k=&raw[off]; off+=klen;
            uint64_t vlen; if(!read_varint(raw.data(), raw.size(), off, vlen)) break;
            if (off+vlen>raw.size()) break; const uint8_t* v=&raw[off]; off+=vlen;
            if (outs.empty()) outs.push_back(Out{});
            Out& O = outs.back();
            if (klen==1 && k[0]==0x03){
                if (vlen!=8) return false; uint64_t val=0; for(int i=0;i<8;i++) val|=(uint64_t)v[i]<<(8*i); O.amount=val;
            } else if (klen==1 && k[0]==0x04){
                size_t o=0; uint64_t sl; if(!read_varint(v, vlen, o, sl)) return false;
                if (o+sl>vlen) return false; O.script.assign(v+o, v+o+sl);
            } else {
                // ignore
            }
            if (off<raw.size() && raw[off]==0x00){ off++; outs.push_back(Out{}); }
        }
        if (!outs.empty() && outs.back().script.empty() && outs.back().amount==0) outs.pop_back();
        out.outs = outs;
        return true;
    }

    static bool from_base64(const std::string& b64, PSBT2& out){
        std::vector<uint8_t> raw; if (!bitcrypto::encoding::base64_decode(b64, raw)) return false;
        return parse(raw, out);
    }
};

inline bool sign_psbt2(PSBT2& P, const uint8_t priv32[32]){
    using namespace bitcrypto;
    U256 d=U256::from_be32(priv32); Secp256k1::scalar_mod_n(d); if (d.is_zero()) return false;
    auto Pub = Secp256k1::derive_pubkey(d); uint8_t pub[65]; size_t plen=0; encode_pubkey(Pub, true, pub, plen);
    uint8_t h160[20]; bitcrypto::hash::hash160(pub, plen, h160);

    bitcrypto::tx::Transaction tx; tx.version = P.tx_version; tx.locktime=0; tx.vin.resize(P.ins.size()); tx.vout.resize(P.outs.size());
    for (size_t i=0;i<P.ins.size();++i){ std::memcpy(tx.vin[i].prevout.txid, P.ins[i].prev_txid, 32); tx.vin[i].prevout.vout=P.ins[i].vout; tx.vin[i].sequence=P.ins[i].sequence; }
    for (size_t i=0;i<P.outs.size();++i){ tx.vout[i].value=P.outs[i].amount; tx.vout[i].scriptPubKey=P.outs[i].script; }

    std::vector<uint64_t> amts(P.ins.size(),0);
    std::vector<std::vector<uint8_t>> spks(P.ins.size());

    for (size_t i=0;i<P.ins.size(); ++i){
        auto& I = P.ins[i];
        uint32_t sh = I.sighash_type ? I.sighash_type : bitcrypto::tx::SIGHASH_ALL;
        if (I.has_witness_utxo){
            amts[i]=I.witness_utxo.value; spks[i]=I.witness_utxo.scriptPubKey;
            if (I.witness_utxo.scriptPubKey.size()==34 && I.witness_utxo.scriptPubKey[0]==0x51 && I.witness_utxo.scriptPubKey[1]==0x20){
                if (!bitcrypto::tx::sign_input_p2tr_keypath(tx, i, priv32, amts, spks, sh)) return false;
                if (tx.vin[i].witness.empty()) return false;
                I.tap_key_sig = tx.vin[i].witness[0];
            } else if (I.witness_utxo.scriptPubKey.size()==22 && I.witness_utxo.scriptPubKey[0]==0x00 && I.witness_utxo.scriptPubKey[1]==0x14){
                if (!bitcrypto::tx::sign_input_p2wpkh(tx, i, priv32, h160, I.witness_utxo.value, sh)) return false;
                std::vector<uint8_t> sig = tx.vin[i].witness[0];
                I.partial_sigs.push_back({std::vector<uint8_t>(pub,pub+plen), sig});
            } else {
                return false;
            }
        } else if (I.has_non_witness_utxo){
            if (!bitcrypto::tx::sign_input_p2pkh(tx, i, priv32, h160, sh)) return false;
            std::vector<uint8_t> ss = tx.vin[i].scriptSig;
            if (ss.empty()) return false; size_t sz=ss[0]; if (ss.size()<1+sz) return false;
            std::vector<uint8_t> sig(ss.begin()+1, ss.begin()+1+sz);
            I.partial_sigs.push_back({std::vector<uint8_t>(pub,pub+plen), sig});
        } else return false;
    }
    tx.set_segwit_if_any_witness();
    return true;
}

inline bool finalize_psbt2(const PSBT2& P, bitcrypto::tx::Transaction& out_tx){
    bitcrypto::tx::Transaction tx; tx.version=P.tx_version; tx.locktime=0; tx.vin.resize(P.ins.size()); tx.vout.resize(P.outs.size());
    for (size_t i=0;i<P.ins.size();++i){ std::memcpy(tx.vin[i].prevout.txid, P.ins[i].prev_txid, 32); tx.vin[i].prevout.vout=P.ins[i].vout; tx.vin[i].sequence=P.ins[i].sequence; }
    for (size_t i=0;i<P.outs.size();++i){ tx.vout[i].value=P.outs[i].amount; tx.vout[i].scriptPubKey=P.outs[i].script; }
    for (size_t i=0;i<P.ins.size();++i){
        const auto& I = P.ins[i];
        if (I.has_witness_utxo){
            auto& spk = I.witness_utxo.scriptPubKey;
            if (spk.size()==34 && spk[0]==0x51 && spk[1]==0x20){
                if (I.tap_key_sig.empty()) return false; tx.vin[i].witness = { I.tap_key_sig };
            } else if (spk.size()==22 && spk[0]==0x00 && spk[1]==0x14){
                if (I.partial_sigs.empty()) return false; const auto& pr = I.partial_sigs[0];
                tx.vin[i].witness.clear(); tx.vin[i].witness.push_back(pr.second); tx.vin[i].witness.push_back(pr.first);
            } else return false;
        } else if (I.has_non_witness_utxo){
            if (I.partial_sigs.empty()) return false; const auto& pr = I.partial_sigs[0];
            std::vector<uint8_t> ss; if (pr.second.size()>=0x4c) return false; ss.push_back((uint8_t)pr.second.size()); ss.insert(ss.end(), pr.second.begin(), pr.second.end());
            if (pr.first.size()>=0x4c) return false; ss.push_back((uint8_t)pr.first.size()); ss.insert(ss.end(), pr.first.begin(), pr.first.end());
            tx.vin[i].scriptSig = ss;
        } else return false;
    }
    tx.set_segwit_if_any_witness(); out_tx = tx; return true;
}

}} // ns
