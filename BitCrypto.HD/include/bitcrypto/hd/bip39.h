#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
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

}}