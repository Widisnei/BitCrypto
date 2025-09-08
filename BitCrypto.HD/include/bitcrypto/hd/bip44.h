#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cctype>
namespace bitcrypto { namespace hd {
inline bool parse_bip44_path(const std::string& path, std::vector<uint32_t>& out){
    out.clear();
    if (path.empty()) return false;
    size_t i=0;
    if (path[0]=='m' || path[0]=='M'){ if (path.size()>1 && path[1]!='/') return false; i = (path.size()>1)?2:1; }
    while (i < path.size()){
        uint64_t val=0; bool hardened=false; size_t start=i;
        while (i<path.size() && std::isdigit((unsigned char)path[i])){ val = val*10 + (path[i]-'0'); i++; }
        if (i==start) return false;
        if (i<path.size() && (path[i]=='\'' || path[i]=='h' || path[i]=='H')){ hardened=true; i++; }
        if (val > 0x7FFFFFFFull) return false;
        uint32_t idx = (uint32_t)val; if (hardened) idx |= 0x80000000u;
        out.push_back(idx);
        if (i==path.size()) break;
        if (path[i]!='/') return false; i++;
    }
    return true;
}
}}