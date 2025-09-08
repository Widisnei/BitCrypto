#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
namespace bitcrypto { namespace encoding {

static inline const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

inline std::string base58_encode(const uint8_t* data, size_t len){
    if (!data || len==0) return std::string();
    size_t zeros=0; while (zeros<len && data[zeros]==0) zeros++;
    std::vector<uint8_t> b(data, data+len);
    std::vector<char> out; out.reserve(len*2);
    size_t start=zeros;
    while (start < b.size()){
        int carry=0;
        for (size_t i=start;i<b.size();i++){
            int x = (carry<<8) | b[i];
            b[i] = (uint8_t)(x / 58);
            carry = x % 58;
        }
        out.push_back(BASE58_ALPHABET[carry]);
        while (start<b.size() && b[start]==0) start++;
    }
    for (size_t i=0;i<zeros;i++) out.push_back('1');
    std::reverse(out.begin(), out.end());
    return std::string(out.begin(), out.end());
}

inline bool base58_decode(const std::string& s, std::vector<uint8_t>& out_bytes){
    if (s.empty()){ out_bytes.clear(); return true; }
    int map[128]; for (int i=0;i<128;i++) map[i]=-1;
    for (int i=0;i<58;i++) map[(int)BASE58_ALPHABET[i]] = i;
    size_t zeros=0; while (zeros<s.size() && s[zeros]=='1') zeros++;
    std::vector<uint8_t> b58; b58.reserve(s.size());
    for (char c : s){
        if ((unsigned char)c>=128 || map[(int)c]==-1) return false;
        b58.push_back((uint8_t)map[(int)c]);
    }
    std::vector<uint8_t> b256; b256.reserve(s.size());
    size_t start=zeros;
    while (start < b58.size()){
        int carry=0;
        for (size_t i=start;i<b58.size();i++){
            int x = carry*58 + b58[i];
            b58[i] = (uint8_t)(x / 256);
            carry = x % 256;
        }
        b256.push_back((uint8_t)carry);
        while (start<b58.size() && b58[start]==0) start++;
    }
    out_bytes.assign(zeros, 0x00);
    for (auto it=b256.rbegin(); it!=b256.rend(); ++it) out_bytes.push_back(*it);
    return true;
}

}} // ns
