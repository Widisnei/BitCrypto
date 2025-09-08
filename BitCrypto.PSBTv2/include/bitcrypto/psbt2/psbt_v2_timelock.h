#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include "psbt_v2.h"

namespace bitcrypto { namespace psbt2 {

// Decodifica ScriptNum (mínimo; sem sinal) em vetor 'num' (little-endian) conforme pushes do Bitcoin Script.
static inline bool decode_scriptnum_minimal(const std::vector<uint8_t>& num, uint64_t& out){
    out = 0;
    if (num.empty()) return true;
    if (num.size() > 8) return false; // limit practical
    // last byte sign bit must be clear for non-negative encoding
    if ((num.back() & 0x80) != 0) return false;
    for (size_t i=0;i<num.size();++i){ out |= (uint64_t)num[i] << (8*i); }
    return true;
}

// Varre wscript procurando '<n> OP_CLTV OP_DROP' ou '<n> OP_CSV OP_DROP' e retorna as dicas.
static inline void extract_timelock_hints_from_wscript(const std::vector<uint8_t>& ws, uint64_t& cltv_min, uint64_t& csv_min){
    cltv_min = 0; csv_min = 0;
    for (size_t i=0;i<ws.size();){
        uint8_t op = ws[i++];
        size_t len=0, off=i;
        if (op==0x00){ len=0; } // OP_0
        else if (op>=0x01 && op<=0x4b){ len=op; if (i+len>ws.size()) return; off=i; i+=len; }
        else if (op==0x4c){ if (i>=ws.size()) return; len=ws[i]; off=i+1; i+=1+len; if (i>ws.size()) return; }
        else if (op==0x4d){ if (i+1>=ws.size()) return; len=ws[i] | ((size_t)ws[i+1]<<8); off=i+2; i+=2+len; if (i>ws.size()) return; }
        else { continue; } // non-push, keep scanning
        // check next two opcodes for CLTV/CSV then DROP
        if (i+2 <= ws.size()){
            uint8_t op1 = ws[i]; uint8_t op2 = (i+1<ws.size()? ws[i+1] : 0);
            if (op1==0xB1 && op2==0x75){ // CLTV + DROP
                std::vector<uint8_t> num(ws.begin()+off, ws.begin()+off+len); uint64_t n=0; if (decode_scriptnum_minimal(num, n)){ if (n>cltv_min) cltv_min=n; }
            } else if (op1==0xB2 && op2==0x75){ // CSV + DROP
                std::vector<uint8_t> num(ws.begin()+off, ws.begin()+off+len); uint64_t n=0; if (decode_scriptnum_minimal(num, n)){ if (n>csv_min) csv_min=n; }
            }
        }
    }
}

// Aplica as dicas (se existirem) ajustando locktime global e sequence por entrada.
static inline void apply_timelock_hints(PSBT2& P){
    // Ajuste de locktime global: max de todos os CLTVs vistos nos witness_scripts
    uint64_t want_lock = 0;
    for (size_t i=0;i<P.ins.size(); ++i){
        const auto& in = P.ins[i];
        uint64_t cltv=0, csv=0;
        if (in.has_witness_script){
            extract_timelock_hints_from_wscript(in.witness_script, cltv, csv);
        }
        if (cltv > want_lock) want_lock = cltv;
        if (csv > 0){
            uint32_t cur = P.ins[i].sequence;
            if (cur == 0xFFFFFFFF || cur < csv) P.ins[i].sequence = (uint32_t)csv;
        }
    }
    if (want_lock > P.locktime) P.locktime = (uint32_t)want_lock;
}

}} // ns
