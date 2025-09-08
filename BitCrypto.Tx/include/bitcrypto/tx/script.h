#pragma once
#include <cstdint>
#include <vector>
#include <string>
namespace bitcrypto { namespace tx {

// Opcodes mínimos usados
enum OPCODE : uint8_t {
    OP_0 = 0x00, OP_DUP = 0x76, OP_HASH160 = 0xA9, OP_EQUAL = 0x87, OP_EQUALVERIFY = 0x88, OP_CHECKSIG = 0xAC, OP_1 = 0x51
};

inline void push_data(const std::vector<uint8_t>& data, std::vector<uint8_t>& out){
    size_t n=data.size();
    if (n<0x4c){ out.push_back((uint8_t)n); out.insert(out.end(), data.begin(), data.end()); }
    else { /* não usamos PUSHDATA1+ neste módulo de alto nível */ out.clear(); }
}

inline std::vector<uint8_t> script_p2pkh(const uint8_t h160[20]){
    std::vector<uint8_t> s; s.reserve(25);
    s.push_back(OP_DUP); s.push_back(OP_HASH160); s.push_back(0x14);
    s.insert(s.end(), h160, h160+20); s.push_back(OP_EQUALVERIFY); s.push_back(OP_CHECKSIG);
    return s;
}

inline std::vector<uint8_t> script_p2wpkh(const uint8_t h160[20]){
    std::vector<uint8_t> s; s.reserve(22);
    s.push_back(0x00); s.push_back(0x14);
    s.insert(s.end(), h160, h160+20);
    return s;
}

inline std::vector<uint8_t> script_p2tr(const uint8_t xonly[32]){
    std::vector<uint8_t> s; s.reserve(34);
    s.push_back(OP_1); s.push_back(0x20);
    s.insert(s.end(), xonly, xonly+32);
    return s;
}

}} // ns
