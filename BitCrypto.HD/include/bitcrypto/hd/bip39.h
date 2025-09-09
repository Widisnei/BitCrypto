#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/pbkdf2_hmac_sha512.h>

namespace bitcrypto { namespace hd {

// Normalização simples (lowercase + trim). Para NFKD completo, considerar extensão futura.
inline std::string normalize_str(const std::string& s){
    std::string t; t.reserve(s.size());
    // trim simples e lowercase ASCII
    size_t a=0,b=s.size(); while(a<b && (s[a]==' '||s[a]=='\t'||s[a]=='\n'||s[a]=='\r')) a++; while(b>a && (s[b-1]==' '||s[b-1]=='\t'||s[b-1]=='\n'||s[b-1]=='\r')) b--;
    for (size_t i=a;i<b;i++){ char c=s[i]; if (c>='A'&&c<='Z') c=('a'+(c-'A')); t.push_back(c); }
    return t;
}

// Deriva a SEED (64 bytes) a partir de um "mnemonic" e "passphrase" conforme BIP-39.
// O "mnemonic" é tratado como texto arbitrário (UTF-8). A validação por wordlist/checksum é opcional.
inline void bip39_seed_from_mnemonic(const std::string& mnemonic, const std::string& passphrase, uint8_t out64[64]){
    using namespace bitcrypto::hash;
    std::string m = normalize_str(mnemonic);
    std::string salt = std::string("mnemonic") + passphrase;
    pbkdf2_hmac_sha512((const uint8_t*)m.data(), m.size(), (const uint8_t*)salt.data(), salt.size(), 2048, out64, 64);
}

inline bool load_wordlist(const std::vector<std::string>& lines, std::vector<std::string>& out){
    out = lines; return out.size()==2048;
}

inline bool entropy_to_mnemonic(const uint8_t* entropy, size_t entlen, const std::vector<std::string>& wl, std::string& phrase){
    if (wl.size()!=2048 || entlen<16 || entlen>32 || entlen%4) return false;
    using namespace bitcrypto::hash;
    uint8_t hash[32]; sha256(entropy, entlen, hash);
    size_t cs = entlen/4; size_t total = entlen*8 + cs; // bits
    std::vector<int> idx(total/11);
    for (size_t i=0;i<idx.size();i++){
        int val=0;
        for (int b=0;b<11;b++){
            size_t bit = i*11 + b;
            int bitv;
            if (bit < entlen*8) bitv = (entropy[bit/8]>>(7-(bit%8)))&1; else bitv = (hash[(bit-entlen*8)/8]>>(7-((bit-entlen*8)%8)))&1;
            val = (val<<1) | bitv;
        }
        idx[i]=val;
    }
    std::ostringstream oss;
    for (size_t i=0;i<idx.size();i++){ if(i) oss<<' '; oss<<wl[idx[i]]; }
    phrase = oss.str();
    return true;
}

inline bool mnemonic_generate(const uint8_t* entropy, size_t entlen, const std::vector<std::string>& wl, std::string& phrase){
    return entropy_to_mnemonic(entropy, entlen, wl, phrase);
}

inline bool mnemonic_to_seed(const std::string& mnemonic, const std::string& pass, uint8_t out64[64]){
    bip39_seed_from_mnemonic(mnemonic, pass, out64); return true;
}

}} 