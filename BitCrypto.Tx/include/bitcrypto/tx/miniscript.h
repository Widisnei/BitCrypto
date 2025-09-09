#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <bitcrypto/tx/script.h>

namespace bitcrypto { namespace tx {

static inline bool hex_to_bytes_ms(const std::string& hs, std::vector<uint8_t>& out){
    out.clear(); auto h2n=[&](char c)->int{ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return -1; };
    if (hs.size()%2) return false;
    for (size_t i=0;i<hs.size(); i+=2){ int a=h2n(hs[i]), b=h2n(hs[i+1]); if(a<0||b<0){ out.clear(); return false; } out.push_back((uint8_t)((a<<4)|b)); }
    return true;
}
static inline void op_small(std::vector<uint8_t>& s, int v){
    if (v==0) { s.push_back(0x00); return; }
    if (v<0 || v>16) { s.push_back(0x00); return; }
    s.push_back((uint8_t)(0x50 + v));
}
static inline void push_num(std::vector<uint8_t>& s, uint64_t v){
    if (v==0){ s.push_back(0x00); return; }
    std::vector<uint8_t> tmp; while (v){ tmp.push_back((uint8_t)(v & 0xFF)); v >>= 8; }
    if (tmp.back() & 0x80) tmp.push_back(0x00);
    if (tmp.size() < 0x4c){ s.push_back((uint8_t)tmp.size()); }
    else if (tmp.size() <= 0xFF){ s.push_back(0x4c); s.push_back((uint8_t)tmp.size()); }
    else { s.push_back(0x4d); s.push_back((uint8_t)(tmp.size()&0xFF)); s.push_back((uint8_t)((tmp.size()>>8)&0xFF)); }
    s.insert(s.end(), tmp.begin(), tmp.end());
}
static inline void split_csv(const std::string& s, std::vector<std::string>& out){
    std::stringstream ss(s); std::string it; out.clear();
    while (std::getline(ss, it, ',')){
        size_t a=0; while(a<it.size() && isspace((unsigned char)it[a])) ++a;
        size_t b=it.size(); while(b>a && isspace((unsigned char)it[b-1])) --b; out.push_back(it.substr(a,b-a));
    }
}
static inline bool split_top_two(const std::string& s, std::string& a, std::string& b){
    int depth=0; for (size_t i=0;i<s.size();++i){ char c=s[i]; if(c=='(') depth++; else if(c==')') depth--; else if(c==',' && depth==0){ a = std::string(s.begin(), s.begin()+i); b = std::string(s.begin()+i+1, s.end()); return true; } }
    return false;
}

// Compilador "miniscript-lite" com suporte: pk(), pkh(), multi(), sortedmulti(), after(), older(), and(), or_i(), or_c(), thresh(m,keys...), e wrappers wsh()/sh(wsh()).
// Observação: 'thresh' gera Tapscript (usa OP_CHECKSIGADD), devendo ser usado via ferramentas específicas (ex.: --tapscript-from-ms).
inline bool miniscript_compile(const std::string& minis, std::vector<uint8_t>& wscript){
    wscript.clear();
    auto trim=[](std::string s){ size_t a=0; while(a<s.size() && isspace((unsigned char)s[a])) ++a; size_t b=s.size(); while(b>a && isspace((unsigned char)s[b-1])) --b; return s.substr(a,b-a); };
    std::string m = trim(minis);
    auto starts_with=[&](const char* p)->bool{ return m.rfind(p,0)==0; };
    auto inside_paren=[&]()->std::string{
        size_t p = m.find('('); size_t q = m.rfind(')'); if (p==std::string::npos || q==std::string::npos || q<=p) return std::string();
        return trim(m.substr(p+1, q-p-1));
    };

    // CLTV/CSV
    if (starts_with("after(")){
        std::string n = inside_paren(); if (n.empty()) return false; uint64_t v=0; for(char c:n){ if(c<'0'||c>'9') return false; v=v*10+(c-'0'); }
        push_num(wscript, v); wscript.push_back(0xB1); wscript.push_back(0x75); return true; // OP_CHECKLOCKTIMEVERIFY OP_DROP
    }
    if (starts_with("older(")){
        std::string n = inside_paren(); if (n.empty()) return false; uint64_t v=0; for(char c:n){ if(c<'0'||c>'9') return false; v=v*10+(c-'0'); }
        push_num(wscript, v); wscript.push_back(0xB2); wscript.push_back(0x75); return true; // OP_CHECKSEQUENCEVERIFY OP_DROP
    }

    // Combinadores
    if (starts_with("and(")){
        std::string body = inside_paren(); if (body.empty()) return false; std::string A,B; if(!split_top_two(body,A,B)) return false;
        std::vector<uint8_t> wsA; if (!miniscript_compile(A, wsA)) return false;
        std::vector<uint8_t> wsB; if (!miniscript_compile(B, wsB)) return false;
        wscript.insert(wscript.end(), wsA.begin(), wsA.end());
        wscript.insert(wscript.end(), wsB.begin(), wsB.end());
        return true;
    }
    if (starts_with("or_i(") || starts_with("or_c(")){
        std::string body = inside_paren(); if (body.empty()) return false; std::string A,B; if(!split_top_two(body,A,B)) return false;
        std::vector<uint8_t> wsA, wsB; if (!miniscript_compile(A, wsA)) return false; if (!miniscript_compile(B, wsB)) return false;
        // Modelo: IF <A> ELSE <B> ENDIF. (Nota: 'or_c' mapeado para 'or_i' neste subset).
        wscript.push_back(0x63); // OP_IF
        wscript.insert(wscript.end(), wsA.begin(), wsA.end());
        wscript.push_back(0x67); // OP_ELSE
        wscript.insert(wscript.end(), wsB.begin(), wsB.end());
        wscript.push_back(0x68); // OP_ENDIF
        return true;
    }

    // Primitivas
    if (starts_with("pk(")){
        std::string hex = inside_paren(); std::vector<uint8_t> pub; if(!hex_to_bytes_ms(hex, pub)) return false;
        if (!(pub.size()==33 || pub.size()==65)) return false;
        push_data(pub, wscript); wscript.push_back(0xAC); return true; // OP_CHECKSIG
    }
    if (starts_with("pkh(")){
        std::string hex = inside_paren(); std::vector<uint8_t> h160; if(!hex_to_bytes_ms(hex, h160)) return false;
        if (h160.size()!=20) return false;
        wscript.push_back(0x76); wscript.push_back(0xA9); wscript.push_back(0x14);
        wscript.insert(wscript.end(), h160.begin(), h160.end());
        wscript.push_back(0x88); wscript.push_back(0xAC);
        return true;
    }
    if (starts_with("multi(")){
        std::string params = inside_paren(); if (params.empty()) return false;
        std::vector<std::string> toks; split_csv(params, toks);
        if (toks.size()<2) return false;
        int mreq = std::stoi(toks[0]); int n = (int)toks.size()-1; if (mreq<1 || n<1 || mreq>n || n>16) return false;
        op_small(wscript, mreq);
        for (size_t i=1;i<toks.size();++i){
            std::vector<uint8_t> pub; if (!hex_to_bytes_ms(toks[i], pub)) return false;
            if (!(pub.size()==33 || pub.size()==65)) return false;
            push_data(pub, wscript);
        }
        op_small(wscript, n); wscript.push_back(0xAE); return true; // OP_CHECKMULTISIG
    }
    if (starts_with("sortedmulti(")){
        std::string params = inside_paren(); if (params.empty()) return false;
        std::vector<std::string> toks; split_csv(params, toks);
        if (toks.size()<2) return false;
        int mreq = std::stoi(toks[0]); int n = (int)toks.size()-1; if (mreq<1 || n<1 || mreq>n || n>16) return false;
        std::vector<std::vector<uint8_t>> pubs;
        for (size_t i=1;i<toks.size();++i){
            std::vector<uint8_t> pub; if (!hex_to_bytes_ms(toks[i], pub)) return false;
            if (!(pub.size()==33 || pub.size()==65)) return false; pubs.push_back(pub);
        }
        std::sort(pubs.begin(), pubs.end(), [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b){ return a<b; });
        op_small(wscript, mreq);
        for (auto& pub : pubs) push_data(pub, wscript);
        op_small(wscript, (int)pubs.size()); wscript.push_back(0xAE); return true;
    }
    if (starts_with("thresh(")){
        // tapscript threshold via OP_CHECKSIGADD: 0 <pk1> CHECKSIG <pk2> CHECKSIGADD ... <m> NUMEQUAL
        std::string params = inside_paren(); if (params.empty()) return false;
        std::vector<std::string> toks; split_csv(params, toks);
        if (toks.size()<2) return false;
        int mreq = std::stoi(toks[0]); int n = (int)toks.size()-1; if (mreq<1 || n<1 || mreq>n) return false;
        // start accumulator 0
        wscript.push_back(0x00);
        // first key -> CHECKSIG
        std::vector<uint8_t> pub1; if (!hex_to_bytes_ms(toks[1], pub1)) return false; if (!(pub1.size()==33 || pub1.size()==65)) return false;
        push_data(pub1, wscript); wscript.push_back(0xAC);
        // remaining -> CHECKSIGADD
        for (size_t i=2;i<toks.size(); ++i){
            std::vector<uint8_t> pk; if (!hex_to_bytes_ms(toks[i], pk)) return false; if (!(pk.size()==33 || pk.size()==65)) return false;
            push_data(pk, wscript); wscript.push_back(0xBA); // OP_CHECKSIGADD
        }
        // compare to m
        push_num(wscript, (uint64_t)mreq); wscript.push_back(0x9C); // OP_NUMEQUAL
        return true;
    }

    // wrappers
    if (starts_with("wsh(")){
        std::string inner = inside_paren(); if (inner.empty()) return false; return miniscript_compile(inner, wscript);
    }
    if (starts_with("sh(")){
        std::string inner = inside_paren(); if (inner.empty()) return false;
        if (inner.rfind("wsh(",0)==0){ std::string in2 = inner.substr(4, inner.size()-5); return miniscript_compile(in2, wscript); }
        return false;
    }
    return false;
}

}} // ns
