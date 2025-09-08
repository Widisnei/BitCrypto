#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/encoding/bech32.h>
#include <bitcrypto/tx/miniscript.h>
#include <bitcrypto/tx/tapscript.h>

static std::string hex(const std::vector<uint8_t>& v){ static const char* he="0123456789abcdef"; std::string s; s.resize(v.size()*2); for(size_t i=0;i<v.size();++i){ s[2*i]=he[v[i]>>4]; s[2*i+1]=he[v[i]&15]; } return s; }

int main(int argc, char** argv){
    bool wscript=false, p2wsh=false, p2shwsh=false, wpkh=false, p2shwpkh=false, analyze=false; std::string expr; std::string hrp="tb";
    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--wscript-from-ms" && i+1<argc){ wscript=true; expr=argv[++i]; }
        else if (a=="--p2wsh-from-ms" && i+1<argc){ p2wsh=true; expr=argv[++i]; }
        else if (a=="--p2shwsh-from-ms" && i+1<argc){ p2shwsh=true; expr=argv[++i]; }
        else if (a=="--wpkh-from-ms" && i+1<argc){ wpkh=true; expr=argv[++i]; }
        else if (a=="--p2shwpkh-from-ms" && i+1<argc){ p2shwpkh=true; expr=argv[++i]; }
        else if (a=="--hrp" && i+1<argc){ hrp=argv[++i]; }
        else if (a=="--tapscript-from-ms" && i+1<argc){ tapscript_out=true; expr=argv[++i]; }
        else if (a=="--suggest-lock"){ suggest=true; }
        else if (a=="--analyze-ms" && i+1<argc){ analyze=true; expr=argv[++i]; }
    }
    if (!(wscript||p2wsh||p2shwsh||wpkh||p2shwpkh||analyze)){ std::cerr<<"Uso: --wscript-from-ms|--p2wsh-from-ms|--p2shwsh-from-ms|--wpkh-from-ms|--p2shwpkh-from-ms <expr> [--hrp bc|tb]\n"; return 1; }
    auto is_prefix = [&](const std::string& s, const char* p){ return s.rfind(p,0)==0; };
    // Handle wpkh/sh(wpkh) (no wscript)
    if (wpkh || p2shwpkh){
        if (!is_prefix(expr, "wpkh(") && !is_prefix(expr, "sh(wpkh(")){ std::cerr<<"Expressão esperada: wpkh(<PUBHEX>) ou sh(wpkh(<PUBHEX>))\n"; return 2; }
        auto inside = [&](const std::string& s){ size_t p=s.find('('); size_t q=s.rfind(')'); if(p==std::string::npos||q==std::string::npos||q<=p) return std::string(); return s.substr(p+1,q-p-1); };
        std::string inner = is_prefix(expr, "wpkh(") ? inside(expr) : inside( inside(expr) );
        auto h2n=[&](char c)->int{ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return -1; };
        std::vector<uint8_t> pub; if (inner.size()%2) { std::cerr<<"PUBHEX inválido\n"; return 2; }
        for (size_t i=0;i<inner.size(); i+=2){ int a=h2n(inner[i]), b=h2n(inner[i+1]); if(a<0||b<0){ std::cerr<<"PUBHEX inválido\n"; return 2; } pub.push_back((uint8_t)((a<<4)|b)); }
        if (!(pub.size()==33 || pub.size()==65)){ std::cerr<<"PUBHEX size deve ser 33/65\n"; return 2; }
        uint8_t h160[20]; bitcrypto::hash::hash160(pub.data(), pub.size(), h160);
        std::vector<uint8_t> prog(h160, h160+20);
        std::vector<uint8_t> spk; spk.push_back(0x00); spk.push_back(0x14); spk.insert(spk.end(), prog.begin(), prog.end());
        if (wpkh){
            std::cout<<"scriptPubKey="; for(auto b:spk) std::cout<<std::hex<<std::nouppercase<<std::setfill('0')<<std::setw(2)<<(int)b; std::cout<<"\n";
            std::string addr; bitcrypto::encoding::segwit_addr_encode(addr, hrp, 0, prog);
            std::cout<<"address="<<addr<<"\n";
            return 0;
        } else {
            std::vector<uint8_t> redeem = spk; uint8_t hr[20]; bitcrypto::hash::hash160(redeem.data(), redeem.size(), hr);
            std::vector<uint8_t> spksh; spksh.push_back(0xA9); spksh.push_back(0x14); spksh.push_back(0x14); // wrong length? Let's do proper: A9 14 <20> 87
            spksh.clear(); spksh.push_back(0xA9); spksh.push_back(0x14); spksh.insert(spksh.end(), hr, hr+20); spksh.push_back(0x87);
            std::cout<<"redeemScript="<<hex(redeem)<<"\n";
            std::cout<<"scriptPubKey="<<hex(spksh)<<"\n";
            return 0;
        }
    }
    // Compile wscript-based expressions
    
    if (analyze){
        std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(expr, ws)){ std::cerr<<"Miniscript inválido\n"; return 2; }
        auto hex = [](const std::vector<uint8_t>& v){ static const char* he="0123456789abcdef"; std::string s; s.resize(v.size()*2); for(size_t i=0;i<v.size();++i){ s[2*i]=he[v[i]>>4]; s[2*i+1]=he[v[i]&15]; } return s; };
        auto read_push_number_le = [](const std::vector<uint8_t>& sc, size_t& off, uint64_t& val)->bool{
            if (off >= sc.size()) return false; uint8_t op = sc[off++]; size_t len=0;
            if (op==0x00){ val=0; return true; } else if (op<0x4c){ len=op; }
            else if (op==0x4c){ if (off+1>sc.size()) return false; len=sc[off]; off+=1; }
            else if (op==0x4d){ if (off+2>sc.size()) return false; len=(size_t)sc[off]|((size_t)sc[off+1]<<8); off+=2; }
            else return false;
            if (off+len>sc.size()) return false; uint64_t v=0; for(size_t i=0;i<len;i++){ v|=(uint64_t)sc[off+i]<<(8*i); } off+=len; val=v; return true;
        };
        size_t off=0; uint64_t n=0; uint32_t after_n=0, older_n=0;
        if (read_push_number_le(ws, off, n) && (off+1)<ws.size()){
            if (ws[off]==0xB1 && ws[off+1]==0x75) after_n=(uint32_t)n;
            if (ws[off]==0xB2 && ws[off+1]==0x75) older_n=(uint32_t)n;
        }
        // Compute program hash (wsh)
        uint8_t h[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), h);
        std::vector<uint8_t> prog(h, h+32);
        std::string addr; bitcrypto::encoding::segwit_addr_encode(addr, hrp, 0, prog);
        std::cout<<"wscript="<<hex(ws)<<"\n";
        std::cout<<"wsh="; for(int i=0;i<32;i++){ static const char* he="0123456789abcdef"; std::cout<<he[h[i]>>4]<<he[h[i]&15]; } std::cout<<"\n";
        if (after_n) std::cout<<"after="<<after_n<<"\n";
        if (older_n) std::cout<<"older="<<older_n<<"\n";
        if (!after_n && !older_n) std::cout<<"timelocks=none\n";
        std::cout<<"address="<<addr<<"\n";
        return 0;
    }
    
    std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(expr, ws)){ std::cerr<<"Miniscript inválido\n"; return 2; }
    std::cout<<"wscript="<<hex(ws)<<"\n";
    uint8_t h[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), h);
    std::vector<uint8_t> prog(h, h+32);
    std::vector<uint8_t> spk_wsh; spk_wsh.push_back(0x00); spk_wsh.push_back(0x20); spk_wsh.insert(spk_wsh.end(), prog.begin(), prog.end());
    if (p2wsh){
        std::cout<<"scriptPubKey="<<hex(spk_wsh)<<"\n";
        std::string addr; bitcrypto::encoding::segwit_addr_encode(addr, hrp, 0, prog);
        std::cout<<"address="<<addr<<"\n";
    } else if (p2shwsh){
        std::vector<uint8_t> redeem = spk_wsh; uint8_t h160r[20]; bitcrypto::hash::hash160(redeem.data(), redeem.size(), h160r);
        std::vector<uint8_t> spk; spk.push_back(0xA9); spk.push_back(0x14); spk.insert(spk.end(), h160r, h160r+20); spk.push_back(0x87);
        std::cout<<"redeemScript="<<hex(redeem)<<"\n"; std::cout<<"scriptPubKey="<<hex(spk)<<"\n";
    }

    // --- Taproot: pair-by-hash root (BIP341) ---
    bool pair_by_hash=false; std::string pair_exprs;
    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--taptree-pair-by-hash" && i+1<argc){ pair_by_hash=true; pair_exprs=argv[++i]; }
    }
    if (pair_by_hash){
        auto trim=[](std::string s){ size_t b=s.find_first_not_of(" \t\r\n"); size_t e=s.find_last_not_of(" \t\r\n"); if(b==std::string::npos) return std::string(); return s.substr(b,e-b+1); };
        std::vector<std::string> exprs; size_t start=0;
        while(true){ size_t p=pair_exprs.find(';', start); if(p==std::string::npos){ exprs.push_back(trim(pair_exprs.substr(start))); break; } exprs.push_back(trim(pair_exprs.substr(start, p-start))); start=p+1; }
        std::vector<std::vector<uint8_t>> leaves;
        for (auto& e : exprs){
            if (e.empty()) continue;
            std::vector<uint8_t> ws;
            if (!bitcrypto::tx::miniscript_compile(e, ws)){ std::cerr<<"Miniscript inválido: "<<e<<"\n"; return 2; }
            uint8_t lh[32]; bitcrypto::tx::tapleaf_hash(ws, 0xC0, lh);
            leaves.emplace_back(lh, lh+32);
        }
        if (leaves.empty()){ std::cerr<<"Nenhum leaf.\n"; return 2; }
        auto lexless=[](const std::vector<uint8_t>& A, const std::vector<uint8_t>& B){ for(size_t i=0;i<32;i++){ if (A[i]<B[i]) return true; if (A[i]>B[i]) return false; } return false; };
        std::vector<std::vector<uint8_t>> level = leaves;
        while (level.size()>1){
            std::sort(level.begin(), level.end(), lexless);
            std::vector<std::vector<uint8_t>> next;
            for (size_t i=0;i<level.size(); i+=2){
                if (i+1>=level.size()){ next.push_back(level[i]); break; }
                std::vector<uint8_t> data; data.reserve(64); data.insert(data.end(), level[i].begin(), level[i].end()); data.insert(data.end(), level[i+1].begin(), level[i+1].end());
                std::array<uint8_t,32> h{}; bitcrypto::tx::tagged_hash("TapBranch", data, h.data());
                next.emplace_back(h.begin(), h.end());
            }
            level.swap(next);
        }
        static const char* he="0123456789abcdef"; std::string hx(64,'0'); 
        for(int i=0;i<32;i++){ hx[2*i]=he[(level[0][i]>>4)&15]; hx[2*i+1]=he[level[0][i]&15]; }
        std::cout<<"taptree_root="<<hx<<"\n";
        return 0;
    }

    return 0;
}
