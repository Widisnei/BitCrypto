#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace bitcrypto { namespace tx {

// Gera witness para Tapscript (script-path) simples (folha única):
// stack = [ <sig> , <witness_script> , <control_block> ]
// Pré-requisitos: assinatura Schnorr (64+1 bytes com sighash, já codificada em PSBT), witness_script e control_block.
static inline bool build_taproot_scriptpath_witness(const std::vector<uint8_t>& sig,
                                                    const std::vector<uint8_t>& witness_script,
                                                    const std::vector<uint8_t>& control_block,
                                                    std::vector<std::vector<uint8_t>>& witness_stack,
                                                    std::string& err){
    if (sig.size()<64) { err="assinatura inválida (esperado >=64 bytes)"; return false; }
    if (witness_script.empty()){ err="witness_script ausente"; return false; }
    if (control_block.empty()){ err="control_block ausente"; return false; }
    witness_stack.clear();
    witness_stack.push_back(sig);
    witness_stack.push_back(witness_script);
    witness_stack.push_back(control_block);
    return true;
}

}} // ns
