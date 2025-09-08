#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
namespace bitcrypto { namespace sign {
struct DER{
    // Encode INTEGER (big-endian, minimal): remove zeros à esquerda; prefixar 0x00 se msb=1
    static inline void encode_integer(const uint8_t* be, size_t len, std::vector<uint8_t>& out){
        size_t i=0; while (i+1<len && be[i]==0) i++;
        bool msb = (be[i] & 0x80) != 0;
        out.push_back(0x02);
        size_t n = len - i + (msb?1:0);
        out.push_back((uint8_t)n);
        if (msb) out.push_back(0x00);
        out.insert(out.end(), be+i, be+len);
    }
    static inline std::vector<uint8_t> encode_signature_rs(const uint8_t r[32], const uint8_t s[32]){
        std::vector<uint8_t> seq; encode_integer(r, 32, seq); encode_integer(s, 32, seq);
        std::vector<uint8_t> out; out.push_back(0x30); out.push_back((uint8_t)seq.size()); out.insert(out.end(), seq.begin(), seq.end());
        return out;
    }
    static inline bool decode_integer(const uint8_t* p, size_t n, size_t& off, std::vector<uint8_t>& out_be){
        if (off>=n || p[off++]!=0x02) return false; if (off>=n) return false; uint8_t len = p[off++]; if (off+len>n) return false;
        if (len==0) return false; if (len>1 && p[off]==0x00 && (p[off+1]&0x80)==0) return false; // non-minimal
        out_be.assign(p+off, p+off+len); off+=len; return true;
    }
    static inline bool decode_signature_rs(const uint8_t* der, size_t len, uint8_t r[32], uint8_t s[32]){
        if (len<2 || der[0]!=0x30 || der[1]!=(uint8_t)(len-2)) return false; size_t off=2; std::vector<uint8_t> R,S;
        if (!decode_integer(der, len, off, R)) return false; if (!decode_integer(der, len, off, S)) return false; if (off!=len) return false;
        if (R.size()>33 || S.size()>33) return false; // limitado a <=33 (com 0x00 opcional)
        // copiar alinhando à direita em 32B
        std::memset(r,0,32); std::memset(s,0,32);
        size_t ro = (R.size()>32)?(R.size()-32):0; size_t so = (S.size()>32)?(S.size()-32):0;
        std::memcpy(r+(32-(R.size()-ro)), R.data()+ro, R.size()-ro);
        std::memcpy(s+(32-(S.size()-so)), S.data()+so, S.size()-so);
        return true;
    }
};
}}