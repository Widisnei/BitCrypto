#pragma once
#include <string>
#include "wif.h"
#include "segwit.h"
#include "taproot.h"
namespace bitcrypto { namespace encoding {
enum class AddressKind { INVALID=0, P2PKH=1, P2WPKH=2, P2TR=3 };
inline AddressKind detect_address_kind(const std::string& s){
    uint8_t ver=0, h160[20];
    if (p2pkh_decode_address(s, ver, h160)) return AddressKind::P2PKH;
    bool is_tb=false;
    if (p2wpkh_decode_address(s, is_tb, h160)) return AddressKind::P2WPKH;
    uint8_t p2tr[32];
    if (p2tr_decode_address(s, is_tb, p2tr)) return AddressKind::P2TR;
    return AddressKind::INVALID;
}
}}