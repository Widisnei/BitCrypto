#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include "psbt_v2.h"
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/hash/sha256.h>

namespace bitcrypto { namespace psbt2 {


inline bool verify_psbt2(const PSBT2& P, std::string& err){
    for (size_t oi=0; oi<P.outs.size(); ++oi){ if (P.outs[oi].amount==0){ err="Saída "+std::to_string(oi)+": amount deve ser > 0"; return false; } }
    for (size_t i=0;i<P.ins.size(); ++i){
        const auto& in = P.ins[i];
        std::vector<uint8_t> spk;
        if (in.has_witness_utxo){
            spk = in.witness_utxo.scriptPubKey;
        } else if (in.has_non_witness_utxo){
            if (in.vout >= in.non_witness_utxo.vout.size()){ err="non_witness_utxo vout inválido"; return false; }
            spk = in.non_witness_utxo.vout[in.vout].scriptPubKey;
        } else { err="Entrada "+std::to_string(i)+": sem witness_utxo e sem non_witness_utxo"; return false; }
        if (spk.empty()){ err="Entrada "+std::to_string(i)+": scriptPubKey vazio"; return false; }
        uint8_t buf32[32], h160[20];
        if (is_p2wpkh(spk, h160)){
            if (in.has_witness_script){ err="Entrada "+std::to_string(i)+": witness_script não esperado em P2WPKH"; return false; }
            if (in.has_redeem_script){ err="Entrada "+std::to_string(i)+": redeem_script não esperado em P2WPKH"; return false; }
            continue;
        }
        if (is_p2tr(spk, buf32)){
            if (in.has_witness_script){ err="Entrada "+std::to_string(i)+": witness_script não esperado em P2TR key-path"; return false; }
            if (in.has_redeem_script){ err="Entrada "+std::to_string(i)+": redeem_script não esperado em P2TR"; return false; }
            continue;
        }
        if (is_p2wsh(spk, buf32)){
            if (!in.has_witness_script){ err="Entrada "+std::to_string(i)+": witness_script ausente em P2WSH"; return false; }
            uint8_t h[32]; bitcrypto::hash::sha256(in.witness_script.data(), in.witness_script.size(), h);
            if (std::memcmp(h, buf32, 32)!=0){ err="Entrada "+std::to_string(i)+": witness_script não bate com o programa (sha256)"; return false; }
            if (in.has_redeem_script){ err="Entrada "+std::to_string(i)+": redeem_script não esperado em P2WSH nativo"; return false; }
            continue;
        }
        if (is_p2sh(spk, h160)){
            if (!in.has_redeem_script){ err="Entrada "+std::to_string(i)+": P2SH requer redeem_script"; return false; }
            uint8_t rh[20]; bitcrypto::hash::hash160(in.redeem_script.data(), in.redeem_script.size(), rh);
            if (std::memcmp(rh, h160, 20)!=0){ err="Entrada "+std::to_string(i)+": redeem_script não corresponde ao P2SH (hash160)"; return false; }
            if (in.redeem_script.size()==22 && in.redeem_script[0]==0x00 && in.redeem_script[1]==0x14){
                if (in.has_witness_script){ err="Entrada "+std::to_string(i)+": witness_script não esperado em P2SH-P2WPKH"; return false; }
                continue;
            }
            if (in.redeem_script.size()==34 && in.redeem_script[0]==0x00 && in.redeem_script[1]==0x20){
                if (!in.has_witness_script){ err="Entrada "+std::to_string(i)+": witness_script ausente em P2SH-P2WSH"; return false; }
                uint8_t p[32]; std::memcpy(p, &in.redeem_script[2], 32);
                uint8_t h[32]; bitcrypto::hash::sha256(in.witness_script.data(), in.witness_script.size(), h);
                if (std::memcmp(h, p, 32)!=0){ err="Entrada "+std::to_string(i)+": witness_script não corresponde ao programa do redeem (sha256)"; return false; }
                continue;
            }
            err="Entrada "+std::to_string(i)+": redeem_script P2SH com formato não suportado";
            return false;
        }
        if (is_p2pkh(spk, h160)){
            if (in.has_witness_script || in.has_redeem_script){ err="Entrada "+std::to_string(i)+": scripts extras não esperados em P2PKH"; return false; }
            continue;
        }
        err="Entrada "+std::to_string(i)+": scriptPubKey de tipo não reconhecido";
        return false;
    }
    return true;
}

}} // ns
