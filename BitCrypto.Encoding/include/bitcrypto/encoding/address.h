#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "b58check.h"
#include "bech32.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/hash160.h"

namespace bitcrypto { namespace encoding {

inline bool is_hex_char(char c){ return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'); }
inline bool is_hex_string(const std::string& s){ if(s.empty()) return false; for(char c: s) if(!is_hex_char(c)) return false; return (s.size()%2)==0; }

// Converte endereço (Base58/Bech32/Bech32m) em scriptPubKey.
// testnet: ajusta interpretação de versões (Base58) e HRP (bech32: tb / bc).
inline bool address_to_scriptpubkey(const std::string& addr, bool testnet, std::vector<uint8_t>& spk){
    spk.clear();
    // Bech32/Bech32m (hrp 'bc' ou 'tb' por convenção)
    if (addr.rfind("bc1",0)==0 || addr.rfind("tb1",0)==0){
        std::string hrp; int v=0; std::vector<uint8_t> prog;
        if (!segwit_addr_decode(addr, hrp, v, prog)) return false;
        // valida hrp/ambiente
        if ((testnet && hrp!="tb") || (!testnet && hrp!="bc")) return false;
        if (v==0 && prog.size()==20){
            // P2WPKH
            spk.push_back(0x00); spk.push_back(0x14); spk.insert(spk.end(), prog.begin(), prog.end()); return true;
        } else if (v==1 && prog.size()==32){
            // P2TR
            spk.push_back(0x51); spk.push_back(0x20); spk.insert(spk.end(), prog.begin(), prog.end()); return true;
        } else if (v==0 && prog.size()==32){
            // P2WSH
            spk.push_back(0x00); spk.push_back(0x20); spk.insert(spk.end(), prog.begin(), prog.end()); return true;
        } else return false;
    }
    // Base58Check (P2PKH/P2SH)
    std::vector<uint8_t> payload; if (base58check_decode(addr, payload)){
        if (payload.size()!=21) return false;
        uint8_t ver = payload[0];
        const uint8_t* h = &payload[1];
        // mainnet: P2PKH=0x00, P2SH=0x05; testnet: P2PKH=0x6f, P2SH=0xc4
        if ((!testnet && ver==0x00) || (testnet && ver==0x6f)){
            // P2PKH
            spk.push_back(0x76); spk.push_back(0xa9); spk.push_back(0x14);
            spk.insert(spk.end(), h, h+20);
            spk.push_back(0x88); spk.push_back(0xac); return true;
        } else if ((!testnet && ver==0x05) || (testnet && ver==0xc4)){
            // P2SH
            spk.push_back(0xa9); spk.push_back(0x14);
            spk.insert(spk.end(), h, h+20);
            spk.push_back(0x87); return true;
        } else return false;
    }
    return false;
}

}} // ns
