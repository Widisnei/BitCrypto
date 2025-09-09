#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cctype>
#include <algorithm>

// Implementação independente de Bech32/Bech32m (BIP-0173/BIP-0350).
// - polymod com geradores do padrão
// - expansão do HRP
// - conversão de bits (8<->5)
// - encode/decode bech32(bech32m) e helpers SegWit v0/v1 (P2WPKH/P2TR)

namespace bitcrypto { namespace encoding {

enum class Bech32Variant { BECH32, BECH32M };

static inline uint32_t bech32_polymod(const std::vector<uint8_t>& v){
    uint32_t chk = 1;
    for (auto b : v){
        uint8_t top = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ b;
        if (top & 1) chk ^= 0x3b6a57b2;
        if (top & 2) chk ^= 0x26508e6d;
        if (top & 4) chk ^= 0x1ea119fa;
        if (top & 8) chk ^= 0x3d4233dd;
        if (top & 16) chk ^= 0x2a1462b3;
    }
    return chk;
}

static inline std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp){
    std::vector<uint8_t> ret; ret.reserve(hrp.size()*2+1);
    for (char c : hrp) ret.push_back((uint8_t)(std::tolower((unsigned char)c) >> 5));
    ret.push_back(0);
    for (char c : hrp) ret.push_back((uint8_t)(std::tolower((unsigned char)c) & 31));
    return ret;
}

static inline bool bech32_create_checksum(const std::string& hrp, const std::vector<uint8_t>& data, Bech32Variant var, std::vector<uint8_t>& out){
    std::vector<uint8_t> values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), {0,0,0,0,0,0});
    uint32_t pm = bech32_polymod(values) ^ (var==Bech32Variant::BECH32 ? 1 : 0x2bc830a3);
    out.resize(6);
    for (int i=0;i<6;i++) out[i] = (pm >> (5*(5-i))) & 31;
    return true;
}

static inline bool bech32_verify_checksum(const std::string& hrp, const std::vector<uint8_t>& data, Bech32Variant& out_variant){
    std::vector<uint8_t> values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t pm = bech32_polymod(values);
    if (pm == 1){ out_variant = Bech32Variant::BECH32; return true; }
    if (pm == 0x2bc830a3){ out_variant = Bech32Variant::BECH32M; return true; }
    return false;
}

static inline const char* BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static inline bool bech32_encode(const std::string& hrp, const std::vector<uint8_t>& data, Bech32Variant var, std::string& out){
    // Verifica HRP (1..83 chars)
    if (hrp.empty() || hrp.size()<1 || hrp.size()>83) return false;
    for (char c: hrp){ if (!(33<=c && c<=126)) return false; }
    // lower-case enforcement
    std::string hrp_l = hrp; std::transform(hrp_l.begin(), hrp_l.end(), hrp_l.begin(), [](char c){ return (char)std::tolower((unsigned char)c); });
    std::vector<uint8_t> chk; bech32_create_checksum(hrp_l, data, var, chk);
    out.clear(); out.reserve(hrp_l.size()+1+data.size()+6);
    out += hrp_l; out.push_back('1');
    for (auto b : data) out.push_back(BECH32_ALPHABET[b]);
    for (auto b : chk) out.push_back(BECH32_ALPHABET[b]);
    return true;
}

static inline int bech32_char_index(char c){
    const char* p = std::strchr(BECH32_ALPHABET, c);
    return p ? int(p - BECH32_ALPHABET) : -1;
}

static inline bool bech32_decode(const std::string& s, std::string& hrp_out, std::vector<uint8_t>& data_out, Bech32Variant& var_out){
    hrp_out.clear(); data_out.clear();
    if (s.size() < 8) return false;
    // No mixed case
    bool has_upper=false, has_lower=false;
    for (char c: s){ if (std::isupper((unsigned char)c)) has_upper=true; if (std::islower((unsigned char)c)) has_lower=true; }
    if (has_upper && has_lower) return false;
    // find separator
    size_t pos = s.rfind('1'); if (pos==std::string::npos || pos < 1 || pos+7 > s.size()) return false;
    hrp_out = s.substr(0,pos);
    if (hrp_out.size()>83) return false;
    std::string d = s.substr(pos+1);
    for (auto& c : hrp_out) c = (char)std::tolower((unsigned char)c);
    data_out.reserve(d.size());
    for (char c : d){
        int x = bech32_char_index((char)std::tolower((unsigned char)c));
        if (x < 0) return false;
        data_out.push_back((uint8_t)x);
    }
    if (!bech32_verify_checksum(hrp_out, data_out, var_out)) return false;
    data_out.resize(data_out.size()-6);
    return true;
}

// converte bits (e.g., 8->5 ou 5->8). pad=true insere bits zeros finais.
static inline bool convert_bits(const std::vector<uint8_t>& in, int from_bits, int to_bits, bool pad, std::vector<uint8_t>& out){
    uint32_t acc=0; int bits=0; uint32_t maxv=(1u<<to_bits)-1; out.clear();
    for (auto b : in){
        if ((b>>from_bits)!=0) return false;
        acc = (acc<<from_bits) | b;
        bits += from_bits;
        while (bits >= to_bits){
            bits -= to_bits;
            out.push_back((uint8_t)((acc>>bits) & maxv));
        }
    }
    if (pad){
        if (bits) out.push_back((uint8_t)((acc << (to_bits - bits)) & maxv));
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv)){
        return false;
    }
    return true;
}

// Helpers de endereço SegWit (BIP-173 e BIP-350)
static inline bool segwit_addr_encode(const std::string& hrp, int witver, const std::vector<uint8_t>& prog, std::string& out){
    if (witver < 0 || witver > 16) return false;
    if (prog.size() < 2 || prog.size() > 40) return false;
    std::vector<uint8_t> data; data.push_back((uint8_t)witver);
    std::vector<uint8_t> conv; if (!convert_bits(prog, 8, 5, true, conv)) return false;
    data.insert(data.end(), conv.begin(), conv.end());
    Bech32Variant var = (witver==0) ? Bech32Variant::BECH32 : Bech32Variant::BECH32M;
    return bech32_encode(hrp, data, var, out);
}

static inline bool segwit_addr_decode(const std::string& s, std::string& hrp_out, int& witver_out, std::vector<uint8_t>& prog_out){
    std::vector<uint8_t> data; Bech32Variant var;
    if (!bech32_decode(s, hrp_out, data, var)) return false;
    if (data.empty()) return false;
    int witver = data[0];
    std::vector<uint8_t> conv(data.begin()+1, data.end()), prog;
    if (!convert_bits(conv, 5, 8, false, prog)) return false;
    if (prog.size() < 2 || prog.size() > 40) return false;
    if (witver==0 && var!=Bech32Variant::BECH32) return false;
    if (witver!=0 && var!=Bech32Variant::BECH32M) return false;
    witver_out = witver; prog_out = prog; return true;
}

}} // ns
