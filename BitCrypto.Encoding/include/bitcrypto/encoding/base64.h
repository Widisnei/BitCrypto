#pragma once
#include <string>
#include <vector>

namespace bitcrypto { namespace encoding {
static const char* B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline std::string base64_encode(const std::vector<uint8_t>& in){
    std::string out; size_t i=0; while (i+2<in.size()){
        uint32_t v=(in[i]<<16)|(in[i+1]<<8)|in[i+2]; i+=3;
        out.push_back(B64[(v>>18)&63]); out.push_back(B64[(v>>12)&63]); out.push_back(B64[(v>>6)&63]); out.push_back(B64[v&63]);
    }
    if (i+1==in.size()){
        uint32_t v=(in[i]<<16); out.push_back(B64[(v>>18)&63]); out.push_back(B64[(v>>12)&63]); out.push_back('='); out.push_back('='); 
    } else if (i+2==in.size()){
        uint32_t v=(in[i]<<16)|(in[i+1]<<8); out.push_back(B64[(v>>18)&63]); out.push_back(B64[(v>>12)&63]); out.push_back(B64[(v>>6)&63]); out.push_back('=');
    }
    return out;
}
inline bool base64_decode(const std::string& s, std::vector<uint8_t>& out){
    auto idx=[&](char c)->int{ if('A'<=c&&c<='Z')return c-'A'; if('a'<=c&&c<='z')return c-'a'+26; if('0'<=c&&c<='9')return c-'0'+52; if(c=='+')return 62; if(c=='/')return 63; return -1; };
    out.clear(); size_t i=0; while(i<s.size()){
        if (i+3>=s.size()) return false;
        int a=idx(s[i]), b=idx(s[i+1]); if(a<0||b<0) break;
        int c = s[i+2]=='='?-1:idx(s[i+2]); int d = s[i+3]=='='?-1:idx(s[i+3]); i+=4;
        uint32_t v = (a<<18)|(b<<12)|((c<0?0:c)<<6)|((d<0?0:d));
        out.push_back((v>>16)&0xFF);
        if (c>=0) out.push_back((v>>8)&0xFF);
        if (d>=0) out.push_back(v&0xFF);
    }
    return true;
}
}} // ns
