#pragma once
#include <cstdint>
#include <vector>
#include <cstring>

namespace bitcrypto { namespace tx {

// Constrói witnessScript padrão multisig:  OP_m <pub1:33> ... <pubn:33> OP_n OP_CHECKMULTISIG
inline bool build_wsh_multisig(uint8_t m, const std::vector<std::vector<uint8_t>>& pubkeys33, std::vector<uint8_t>& script_out){
    if (m==0 || pubkeys33.empty() || m>pubkeys33.size()) return false;
    for (auto& pk : pubkeys33) if (pk.size()!=33) return false;
    script_out.clear();
    script_out.push_back(0x50 + m); // OP_m
    for (auto& pk : pubkeys33){
        script_out.push_back(33); script_out.insert(script_out.end(), pk.begin(), pk.end());
    }
    script_out.push_back(0x50 + (uint8_t)pubkeys33.size()); // OP_n
    script_out.push_back(0xAE); // OP_CHECKMULTISIG
    return true;
}

// Faz parse de witnessScript padrão multisig; retorna m e lista de pubkeys (33B).
inline bool parse_wsh_multisig(const std::vector<uint8_t>& script, uint8_t& m_out, std::vector<std::vector<uint8_t>>& pubkeys33_out){
    pubkeys33_out.clear(); m_out=0;
    if (script.size()<1+1+1) return false;
    uint8_t opm = script[0]; if (opm<0x51 || opm>0x60) return false; // OP_1..OP_16
    size_t i=1;
    while (i < script.size()){
        if (i==script.size()-2){ // expecting OP_n OP_CHECKMULTISIG
            uint8_t opn = script[i]; uint8_t last = script[i+1];
            if (!(opn>=0x51 && opn<=0x60 && last==0xAE)) return false;
            uint8_t n = opn - 0x50;
            if (n != pubkeys33_out.size()) return false;
            m_out = opm - 0x50;
            return true;
        }
        uint8_t op = script[i++];
        if (op != 33) return false;
        if (i+33 > script.size()) return false;
        pubkeys33_out.emplace_back(script.begin()+i, script.begin()+i+33);
        i += 33;
    }
    return false;
}

}} // ns
