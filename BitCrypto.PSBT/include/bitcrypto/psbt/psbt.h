#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/encoding/base58.h>
#include <bitcrypto/encoding/b58check.h>
#include <bitcrypto/tx/tx.h>
#include <bitcrypto/tx/sighash.h>

namespace bitcrypto { namespace psbt {

// PSBT v0 mínimo para P2WPKH single-sig (SIGHASH_ALL).
// Serialização binária (não Base64 aqui). CLI poderá aceitar hex.

static const uint8_t PSBT_MAGIC[5] = {'p','s','b','t',0xFF};

struct MapKV { std::vector<uint8_t> key; std::vector<uint8_t> val; };
struct Psbt {
    bitcrypto::tx::Tx unsigned_tx;
    std::vector<std::vector<MapKV>> inputs;  // mapas por input
    std::vector<std::vector<MapKV>> outputs; // mapas por output
};

// Alias para compatibilidade com código legado
using PSBT = Psbt;

// Helpers varint
inline void write_varint(std::vector<uint8_t>& out, uint64_t v){
    if (v < 0xFD){ out.push_back((uint8_t)v); return; }
    else if (v <= 0xFFFF){ out.push_back(0xFD); out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v>>8)&0xFF)); }
    else if (v <= 0xFFFFFFFFULL){ out.push_back(0xFE);
        for (int i=0;i<4;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF));
    } else {
        out.push_back(0xFF); for (int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF));
    }
}
inline bool read_varint(const std::vector<uint8_t>& in, size_t& p, uint64_t& v){
    if (p>=in.size()) return false; uint8_t ch=in[p++];
    if (ch<0xFD){ v=ch; return true; }
    if (ch==0xFD){ if (p+2>in.size()) return false; v = in[p] | (uint64_t)in[p+1]<<8; p+=2; return true; }
    if (ch==0xFE){ if (p+4>in.size()) return false; v=0; for(int i=0;i<4;i++){ v|=(uint64_t)in[p+i]<<(8*i);} p+=4; return true; }
    if (ch==0xFF){ if (p+8>in.size()) return false; v=0; for(int i=0;i<8;i++){ v|=(uint64_t)in[p+i]<<(8*i);} p+=8; return true; }
    return false;
}

inline void write_bytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& b){ out.insert(out.end(), b.begin(), b.end()); }
inline bool read_bytes(const std::vector<uint8_t>& in, size_t& p, size_t n, std::vector<uint8_t>& out){ if(p+n>in.size()) return false; out.assign(in.begin()+p, in.begin()+p+n); p+=n; return true; }

// Serialize/parse length-prefixed (varint)
inline void write_lp(std::vector<uint8_t>& out, const std::vector<uint8_t>& b){ write_varint(out,b.size()); write_bytes(out,b); }
inline bool read_lp(const std::vector<uint8_t>& in, size_t& p, std::vector<uint8_t>& out){ uint64_t n; if(!read_varint(in,p,n)) return false; return read_bytes(in,p,(size_t)n,out); }

// Serialização global: [magic] [0x00 len=0] [map vazio] [unsigned tx]
inline void serialize_unsigned_tx(const bitcrypto::tx::Tx& t, std::vector<uint8_t>& out){
    using namespace bitcrypto::tx;
    std::vector<uint8_t> ser; serialize_legacy(t, ser); // PSBT v0 armazena tx sem witnesses
    write_lp(out, ser);
}
inline bool parse_unsigned_tx(const std::vector<uint8_t>& in, size_t& p, bitcrypto::tx::Tx& t){
    using namespace bitcrypto::tx;
    std::vector<uint8_t> ser; if(!read_lp(in,p,ser)) return false;
    size_t q=0;
    auto read_u32=[&](uint32_t& v)->bool{ if(q+4>ser.size()) return false; v= (uint32_t)ser[q] | ((uint32_t)ser[q+1]<<8) | ((uint32_t)ser[q+2]<<16) | ((uint32_t)ser[q+3]<<24); q+=4; return true; };
    auto read_var=[&](uint64_t& v)->bool{
        if(q>=ser.size()) return false; uint8_t ch=ser[q++];
        if (ch<0xFD){ v=ch; return true; } else if (ch==0xFD){ if(q+2>ser.size()) return false; v=ser[q]|((uint64_t)ser[q+1]<<8); q+=2; return true; }
        else if (ch==0xFE){ if(q+4>ser.size()) return false; v=0; for(int i=0;i<4;i++){ v|=(uint64_t)ser[q+i]<<(8*i);} q+=4; return true; }
        else { if(q+8>ser.size()) return false; v=0; for(int i=0;i<8;i++){ v|=(uint64_t)ser[q+i]<<(8*i);} q+=8; return true; }
    };
    t.has_witness=false;
    if(!read_u32(t.version)) return false;
    uint64_t nin=0; if(!read_var(nin)) return false;
    t.vin.resize((size_t)nin);
    for (size_t i=0;i<nin;i++){
        if(q+32+4>ser.size()) return false;
        std::memcpy(t.vin[i].prevout.txid, ser.data()+q, 32); q+=32;
        t.vin[i].prevout.vout = (uint32_t)ser[q] | ((uint32_t)ser[q+1]<<8) | ((uint32_t)ser[q+2]<<16) | ((uint32_t)ser[q+3]<<24); q+=4;
        uint64_t slen; if(!read_var(slen)) return false; if(q+slen>ser.size()) return false;
        t.vin[i].scriptSig.assign(ser.begin()+q, ser.begin()+q+slen); q+=slen;
        if(q+4>ser.size()) return false; t.vin[i].sequence = (uint32_t)ser[q] | ((uint32_t)ser[q+1]<<8) | ((uint32_t)ser[q+2]<<16) | ((uint32_t)ser[q+3]<<24); q+=4;
    }
    uint64_t nout=0; if(!read_var(nout)) return false; t.vout.resize((size_t)nout);
    for (size_t i=0;i<nout;i++){
        if(q+8>ser.size()) return false; uint64_t v=0; for(int j=0;j<8;j++){ v|=(uint64_t)ser[q+j]<<(8*j);} q+=8; t.vout[i].value=v;
        uint64_t slen; if(!read_var(slen)) return false; if(q+slen>ser.size()) return false;
        t.vout[i].scriptPubKey.assign(ser.begin()+q, ser.begin()+q+slen); q+=slen;
    }
    if(q+4>ser.size()) return false; t.locktime=(uint32_t)ser[q]|((uint32_t)ser[q+1]<<8)|((uint32_t)ser[q+2]<<16)|((uint32_t)ser[q+3]<<24); q+=4;
    return q==ser.size();
}

inline void serialize(const Psbt& psbt, std::vector<uint8_t>& out){
    // magic
    out.insert(out.end(), PSBT_MAGIC, PSBT_MAGIC+5);
    // global map (apenas chave 0x00 => unsigned_tx)
    // Chave: prefixo 0x00 + (nenhum dado)
    std::vector<uint8_t> key{0x00};
    write_lp(out, key);
    serialize_unsigned_tx(psbt.unsigned_tx, out);
    // mapa global termina com 0x00 length
    out.push_back(0x00);

    // inputs
    for (auto& m : psbt.inputs){
        for (auto& kv : m){ write_lp(out, kv.key); write_lp(out, kv.val); }
        out.push_back(0x00);
    }
    // outputs
    for (auto& m : psbt.outputs){
        for (auto& kv : m){ write_lp(out, kv.key); write_lp(out, kv.val); }
        out.push_back(0x00);
    }
}

inline bool parse(const std::vector<uint8_t>& in, Psbt& psbt){
    size_t p=0;
    if (in.size()<5) return false;
    if (!(in[0]=='p' && in[1]=='s' && in[2]=='b' && in[3]=='t' && in[4]==0xFF)) return false;
    p=5;
    // global map: esperamos a chave 0x00 (unsigned tx), depois terminador
    std::vector<uint8_t> key, val;
    if (!read_lp(in,p,key)) return false;
    if (!(key.size()==1 && key[0]==0x00)) return false;
    if (!parse_unsigned_tx(in,p,psbt.unsigned_tx)) return false;
    if (p>=in.size()) return false;
    if (in[p++]!=0x00) return false; // fim do mapa global

    // inputs: igual ao número de vin
    psbt.inputs.resize(psbt.unsigned_tx.vin.size());
    for (size_t i=0;i<psbt.inputs.size();++i){
        while (true){
            if (p>=in.size()) return false;
            if (in[p]==0x00){ p++; break; } // fim mapa input
            if (!read_lp(in,p,key)) return false;
            if (!read_lp(in,p,val)) return false;
            psbt.inputs[i].push_back(MapKV{key,val});
        }
    }
    // outputs
    psbt.outputs.resize(psbt.unsigned_tx.vout.size());
    for (size_t i=0;i<psbt.outputs.size();++i){
        while (true){
            if (p>=in.size()) return false;
            if (in[p]==0x00){ p++; break; } // fim mapa output
            if (!read_lp(in,p,key)) return false;
            if (!read_lp(in,p,val)) return false;
            psbt.outputs[i].push_back(MapKV{key,val});
        }
    }
    return p==in.size();
}

// Chaves PSBT v0 mínimas (prefixos)
static const uint8_t KEY_IN_WITNESS_UTXO = 0x01;
static const uint8_t KEY_IN_PARTIAL_SIG  = 0x02;
static const uint8_t KEY_IN_SIGHASH_TYPE = 0x03;
// (não incluímos outras nesta entrega)

// Assinatura P2WPKH (SIGHASH_ALL) para input i usando privkey
inline bool sign_p2wpkh_input(Psbt& psbt, size_t i, const uint8_t priv32[32]){
    using namespace bitcrypto;
    if (i>=psbt.inputs.size()) return false;
    auto& inmap = psbt.inputs[i];
    // busca WITNESS_UTXO
    std::vector<uint8_t> utxo_ser;
    bool found=false;
    for (auto& kv : inmap){
        if (kv.key.size()==1 && kv.key[0]==KEY_IN_WITNESS_UTXO){ utxo_ser=kv.val; found=true; break; }
    }
    if (!found) return false;
    // parse TxOut: valor(8) + script len + script
    if (utxo_ser.size()<8) return false;
    uint64_t amount=0; for(int j=0;j<8;j++) amount |= (uint64_t)utxo_ser[j]<<(8*j);
    size_t p=8; // scriptPubKey
    // varint
    auto read_var=[&](uint64_t& v)->bool{
        if (p>=utxo_ser.size()) return false; uint8_t ch=utxo_ser[p++];
        if (ch<0xFD){ v=ch; return true; } else if (ch==0xFD){ if (p+2>utxo_ser.size()) return false; v=utxo_ser[p]|((uint64_t)utxo_ser[p+1]<<8); p+=2; return true; }
        else if (ch==0xFE){ if (p+4>utxo_ser.size()) return false; v=0; for(int i=0;i<4;i++){ v|=(uint64_t)utxo_ser[p+i]<<(8*i);} p+=4; return true; }
        else { if (p+8>utxo_ser.size()) return false; v=0; for(int i=0;i<8;i++){ v|=(uint64_t)utxo_ser[p+i]<<(8*i);} p+=8; return true; }
    };
    uint64_t slen=0; if(!read_var(slen)) return false; if (p+slen>utxo_ser.size()) return false;
    std::vector<uint8_t> spk(utxo_ser.begin()+p, utxo_ser.begin()+p+slen);
    // espera-se P2WPKH: 0x00 0x14 <20>
    if (!(spk.size()==22 && spk[0]==0x00 && spk[1]==0x14)) return false;
    const uint8_t* h160 = spk.data()+2;
    auto sc = bitcrypto::tx::scriptCode_p2wpkh(h160);

    // sighash BIP-143
    psbt.unsigned_tx.has_witness=true;
    uint8_t m32[32]; bitcrypto::tx::sighash_segwit_v0_all(psbt.unsigned_tx, i, sc, amount, m32);

    // ECDSA determinístico
    bitcrypto::sign::ECDSA_Signature sig{};
    if (!bitcrypto::sign::ecdsa_sign_rfc6979(priv32, m32, sig)) return false;
    auto der = bitcrypto::sign::der_from_rs(sig.r, sig.s);
    der.push_back(0x01); // sighash all

    // pubkey (33B) a partir de priv
    U256 d=U256::from_be32(priv32); Secp256k1::scalar_mod_n(d); auto P=Secp256k1::derive_pubkey(d); uint8_t pub[65]; size_t plen=0; encode_pubkey(P,true,pub,plen);

    // grava partial sig: key= 0x02 || <pubkey>, val= sigDER||sighash
    std::vector<uint8_t> k; k.push_back(KEY_IN_PARTIAL_SIG); k.insert(k.end(), pub, pub+33);
    inmap.push_back(MapKV{k, der});
    return true;
}

// Finaliza P2WPKH: converte partial sig + pubkey em testemunha [sig, pubkey] e limpa partials
inline bool finalize_p2wpkh(Psbt& psbt, size_t i){
    if (i>=psbt.inputs.size()) return false;
    auto& inmap = psbt.inputs[i];
    std::vector<uint8_t> sig, pub;
    // coleta primeira partial sig
    for (auto& kv : inmap){
        if (kv.key.size()==1+33 && kv.key[0]==KEY_IN_PARTIAL_SIG){
            pub.assign(kv.key.begin()+1, kv.key.end());
            sig = kv.val; break;
        }
    }
    if (sig.empty() || pub.size()!=33) return false;
    // aplica witness e zera scriptSig
    if (i>=psbt.unsigned_tx.vin.size()) return false;
    auto& in = psbt.unsigned_tx.vin[i];
    in.scriptSig.clear();
    in.witness.clear();
    in.witness.push_back(sig);
    in.witness.push_back(pub);
    psbt.unsigned_tx.has_witness=true;
    // remove partials simples
    std::vector<MapKV> outm;
    for (auto& kv : inmap) if (!(kv.key.size()==34 && kv.key[0]==KEY_IN_PARTIAL_SIG)) outm.push_back(kv);
    inmap.swap(outm);
    return true;
}

}} // ns
