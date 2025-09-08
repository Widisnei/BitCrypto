#pragma once
#include <cstdint>
#include <vector>
#include <cstddef>
namespace bitcrypto { namespace tx {
inline void ser_varint(uint64_t v, std::vector<uint8_t>& out){
    if (v < 0xFD){ out.push_back((uint8_t)v); }
    else if (v <= 0xFFFF){ out.push_back(0xFD); out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); }
    else if (v <= 0xFFFFFFFFULL){ out.push_back(0xFE); for (int i=0;i<4;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF)); }
    else { out.push_back(0xFF); for (int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF)); }
}
inline bool deser_varint(const std::vector<uint8_t>& in, size_t& pos, uint64_t& v){
    if (pos>=in.size()) return false; uint8_t ch = in[pos++];
    if (ch < 0xFD){ v = ch; return true; }
    if (ch==0xFD){ if (pos+2>in.size()) return false; v = (uint64_t)in[pos] | ((uint64_t)in[pos+1]<<8); pos+=2; return true; }
    if (ch==0xFE){ if (pos+4>in.size()) return false; v = 0; for (int i=0;i<4;i++) v |= (uint64_t)in[pos+i]<<(8*i); pos+=4; return true; }
    if (pos+8>in.size()) return false; v=0; for (int i=0;i<8;i++) v |= (uint64_t)in[pos+i]<<(8*i); pos+=8; return true;
}
}} // ns
