#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
namespace bitcrypto { namespace encoding {
inline void der_push_len(std::vector<uint8_t>& out, size_t len){
    if (len < 128) out.push_back((uint8_t)len);
    else { uint8_t tmp[9]; int n=0; size_t x=len; while (x){ tmp[++n]=(uint8_t)(x & 0xFF); x >>= 8; } out.push_back((uint8_t)(0x80 | n)); for (int i=n;i>=1;i--) out.push_back(tmp[i]); }
}
inline size_t der_read_len(const uint8_t* p, size_t len, size_t& o){
    if (len==0) return (size_t)-1; uint8_t b = *p++; o=1; if (b<128) return b;
    size_t n = b & 0x7F; if (n==0 || n>sizeof(size_t) || n>len-1) return (size_t)-1;
    size_t L=0; for (size_t i=0;i<n;i++){ L=(L<<8)|(*p++); } o=1+n; return L;
}
inline void der_minimal_int(const uint8_t x32[32], std::vector<uint8_t>& out_int){
    size_t i=0; while (i<32 && x32[i]==0) i++;
    if (i==32){ out_int.assign(1,0x00); return; }
    bool msb = (x32[i]&0x80)!=0; if (msb){ out_int.resize(1+(32-i)); out_int[0]=0x00; std::memcpy(&out_int[1], &x32[i], 32-i); } else { out_int.assign(&x32[i], &x32[32]); }
}
inline bool der_parse_int(const uint8_t* p, size_t len, size_t& used, uint8_t out32[32]){
    if (len<2 || p[0]!=0x02) return false; size_t l_off=0; size_t L = der_read_len(p+1, len-1, l_off); if (L==(size_t)-1 || 1+l_off+L>len) return false;
    const uint8_t* q = p+1+l_off; if (L==0) return false; if (q[0]==0x00 && L>=2 && (q[1]&0x80)==0) return false; if ((q[0]&0x80)!=0) return false;
    std::memset(out32, 0, 32); if (L>32) return false; std::memcpy(out32+(32-L), q, L); used = 1+l_off+L; return true;
}
inline bool ecdsa_der_encode(const uint8_t r32[32], const uint8_t s32[32], std::vector<uint8_t>& out){
    std::vector<uint8_t> R,S; der_minimal_int(r32,R); der_minimal_int(s32,S); if (R.empty()||S.empty()) return false;
    out.clear(); out.push_back(0x30); std::vector<uint8_t> inner; inner.push_back(0x02); der_push_len(inner,R.size()); inner.insert(inner.end(),R.begin(),R.end()); inner.push_back(0x02); der_push_len(inner,S.size()); inner.insert(inner.end(),S.begin(),S.end()); der_push_len(out, inner.size()); out.insert(out.end(), inner.begin(), inner.end()); return true;
}
inline bool ecdsa_der_decode(const uint8_t* sig, size_t len, uint8_t r32[32], uint8_t s32[32]){
    if (len<8 || sig[0]!=0x30) return false; size_t l_off=0; size_t L=der_read_len(sig+1, len-1, l_off); if (L==(size_t)-1 || 1+l_off+L!=len) return false;
    size_t pos=1+l_off, used=0; if (!der_parse_int(sig+pos, len-pos, used, r32)) return false; pos+=used; if (!der_parse_int(sig+pos, len-pos, used, s32)) return false; pos+=used; if (pos!=len) return false; return true;
}}
