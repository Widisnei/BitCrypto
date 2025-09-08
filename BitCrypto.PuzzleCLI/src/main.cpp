
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <iomanip>
#include <unordered_map>
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"

using namespace bitcrypto;

static bool hex_to_bytes(const std::string& s, std::vector<uint8_t>& out){
    if (s.size()%2) return false; out.resize(s.size()/2);
    auto hv=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+c-'a'; if(c>='A'&&c<='F')return 10+c-'A'; return -1; };
    for (size_t i=0;i<s.size();i+=2){ int hi=hv(s[i]), lo=hv(s[i+1]); if(hi<0||lo<0) return false; out[i/2]=(uint8_t)((hi<<4)|lo); }
    return true;
}
static std::string bytes_to_hex(const uint8_t* p,size_t n){ std::ostringstream o; o<<std::hex<<std::nouppercase<<std::setfill('0'); for(size_t i=0;i<n;i++) o<<std::setw(2)<<(int)p[i]; return o.str(); }

int main(int argc, char** argv){
    bool kang=false; std::string pub_hex, range;
    for (int i=1;i<argc;i++){
        std::string a(argv[i]);
        if (a=="--kangaroo") kang=true;
        else if (a=="--pub" && i+1<argc) pub_hex=argv[++i];
        else if (a=="--range" && i+1<argc) range=argv[++i];
    }
    if (!kang){ std::cerr<<"Uso: BitCrypto.PuzzleCLI --kangaroo --pub <hex33|65> --range <a..b>\n"; return 1; }

    // Parse range
    size_t p = range.find(".."); if (p==std::string::npos){ std::cerr<<"range inválido\n"; return 1; }
    std::string as=range.substr(0,p), bs=range.substr(p+2);
    uint64_t a=std::strtoull(as.c_str(),nullptr,10), b=std::strtoull(bs.c_str(),nullptr,10);
    if (a>=b || (b-a) > 2000000ULL){ std::cerr<<"intervalo muito grande para demo CPU\n"; return 2; }

    std::vector<uint8_t> pub; if(!hex_to_bytes(pub_hex, pub)){ std::cerr<<"pub inválida\n"; return 1; }
    bitcrypto::ECPointA Q; if (!bitcrypto::parse_pubkey(pub.data(), pub.size(), Q)){ std::cerr<<"pub parse falhou\n"; return 1; }

    // Baby-step giant-step (mais simples e adequado a intervalos pequenos)
    // Precompute baby steps: i*G para i in [0..m)
    uint64_t m = (uint64_t)std::ceil(std::sqrt((double)(b-a)));
    std::unordered_map<std::string, uint64_t> table; table.reserve((size_t)m*2);
    bitcrypto::ECPointA G = bitcrypto::Secp256k1::G();
    bitcrypto::ECPointA P; // P = a*G
    {
        bitcrypto::U256 kk{{a,0,0,0}};
        P = bitcrypto::Secp256k1::to_affine(bitcrypto::Secp256k1::scalar_mul(kk, G));
    }
    auto key_of = [&](const bitcrypto::ECPointA& A){
        uint8_t xb[33]; size_t l=0; encode_pubkey(A,true,xb,l); return bytes_to_hex(xb,l);
    };
    table[key_of(P)] = 0;
    bitcrypto::ECPointJ cur = bitcrypto::Secp256k1::to_jacobian(P);
    for (uint64_t i=1;i<m;i++){
        cur = bitcrypto::Secp256k1::add(cur, bitcrypto::Secp256k1::to_jacobian(G));
        bitcrypto::ECPointA aff = bitcrypto::Secp256k1::to_affine(cur);
        table[key_of(aff)] = i;
    }
    // Giant steps: Q - j*m*G  (busca colisão)
    bitcrypto::U256 step{{m,0,0,0}}, jm{{0,0,0,0}};
    bitcrypto::ECPointA mG = bitcrypto::Secp256k1::to_affine(bitcrypto::Secp256k1::scalar_mul(step, G));
    bitcrypto::ECPointA T = Q;
    for (uint64_t j=0; j<=m; ++j){
        std::string k = key_of(T);
        auto it = table.find(k);
        if (it != table.end()){
            uint64_t i = it->second;
            uint64_t kval = a + i + j*m;
            if (kval <= b){
                std::cout<<"kangaroo_found k="<<kval<<"\n"; return 0;
            }
        }
        // T = T - mG
        bitcrypto::ECPointA nG = mG; bitcrypto::Fp ny; ny = bitcrypto::Fp::sub(bitcrypto::Fp::zero(), nG.y); nG.y = ny;
        T = bitcrypto::Secp256k1::to_affine(bitcrypto::Secp256k1::add(bitcrypto::Secp256k1::to_jacobian(T), bitcrypto::Secp256k1::to_jacobian(nG)));
    }
    std::cout<<"kangaroo_not_found\n"; return 3;
}
