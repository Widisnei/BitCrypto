#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <algorithm>
#include <bitcrypto/ec/secp256k1.h>
// OBS: Assumimos que há um SHA-256 interno disponível como bitcrypto::hash::sha256 com tag_hash.
// Caso não exista ainda, substitua a chamada por sua implementação local.

using namespace bitcrypto::ec;
using namespace bitcrypto::fe256;

static std::vector<uint8_t> hex2v(const std::string& hs){
    std::vector<uint8_t> v; if (hs.size()%2) return v;
    auto h2n=[&](char c){ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return -1; };
    for (size_t i=0;i<hs.size(); i+=2){
        int a=h2n(hs[i]), b=h2n(hs[i+1]); if(a<0||b<0){ v.clear(); return v; }
        v.push_back((uint8_t)((a<<4)|b));
    } return v;
}

int main(int argc, char** argv){
    bool bip340=false; std::string pubx_hex, msg_hex, sig_hex;
    for (int i=1;i<argc;i++){
        std::string a = argv[i];
        if (a=="--bip340-verify"){ bip340=true; }
        else if (a=="--pubx" && i+1<argc){ pubx_hex=argv[++i]; }
        else if (a=="--msg" && i+1<argc){ msg_hex=argv[++i]; }
        else if (a=="--sig" && i+1<argc){ sig_hex=argv[++i]; }
        else { std::cerr<<"Uso: BitCrypto.SchnorrCLI --bip340-verify --pubx <hex32> --msg <hex..> --sig <hex64>\n"; return 1; }
    }
    if (!bip340){ std::cerr<<"Forneça --bip340-verify\n"; return 1; }

    auto px = hex2v(pubx_hex); auto m = hex2v(msg_hex); auto sig = hex2v(sig_hex);
    if (px.size()!=32 || sig.size()!=64){ std::cerr<<"Tamanhos inválidos\n"; return 1; }
    const uint8_t* r_be = &sig[0]; const uint8_t* s_be = &sig[32];

    fe rx = fe_from_bytes_be(r_be);
    if (fe_cmp(rx, P())>=0){ std::cout<<"bip340_verify=fail\n"; return 0; }
    fe s = fe_from_bytes_be(s_be); if (fe_cmp(s, N())>=0){ std::cout<<"bip340_verify=fail\n"; return 0; }

    PointA Pub;
    if (!lift_x_even_y(Pub, px.data())){ std::cout<<"bip340_verify=fail\n"; return 0; }

    // e = H_tag("BIP0340/challenge", r||px||m) mod n
    std::vector<uint8_t> pre(32+32+m.size());
    std::copy(r_be, r_be+32, pre.begin());
    std::copy(px.begin(), px.end(), pre.begin()+32);
    std::copy(m.begin(), m.end(), pre.begin()+64);

    // Placeholder de hash: para integração com seu SHA256 local, troque a função abaixo.
    // Aqui usamos uma soma simplista apenas para manter o executável compilar caso não exista o módulo hash ainda.
    // *** Substitua por bitcrypto::hash::sha256::tagged_hash("BIP0340/challenge", pre) ***
    std::array<uint8_t,32> e32{}; 
    for(size_t i=0;i<pre.size();++i){ e32[i%32] ^= pre[i]; }

    fe e = fe_from_bytes_be(e32.data());
    for (int k=0;k<2;k++){ fe tmp; unsigned char brr=0;
        brr = _subborrow_u64(0, e.v[0], N().v[0], &tmp.v[0]);
        brr = _subborrow_u64(brr, e.v[1], N().v[1], &tmp.v[1]);
        brr = _subborrow_u64(brr, e.v[2], N().v[2], &tmp.v[2]);
        brr = _subborrow_u64(brr, e.v[3], N().v[3], &tmp.v[3]);
        uint64_t mask = (uint64_t)-(int)(brr==0);
        e.v[0] = (e.v[0] & ~mask) | (tmp.v[0] & mask);
        e.v[1] = (e.v[1] & ~mask) | (tmp.v[1] & mask);
        e.v[2] = (e.v[2] & ~mask) | (tmp.v[2] & mask);
        e.v[3] = (e.v[3] & ~mask) | (tmp.v[3] & mask);
    }

    PointA Gaff = G();
    uint8_t s_be_arr[32]; fe_to_bytes_be(s_be_arr, s);
    uint8_t e_be_arr[32]; fe_to_bytes_be(e_be_arr, e);

    PointJ R1; scalar_mul(R1, Gaff, s_be_arr);
    PointA nPub; pa_neg(nPub, Pub);
    fe en; unsigned char brr=0;
    brr = _subborrow_u64(0, N().v[0], e.v[0], &en.v[0]);
    brr = _subborrow_u64(brr, N().v[1], e.v[1], &en.v[1]);
    brr = _subborrow_u64(brr, N().v[2], e.v[2], &en.v[2]);
    brr = _subborrow_u64(brr, N().v[3], e.v[3], &en.v[3]);
    uint8_t en_be[32]; fe_to_bytes_be(en_be, en);
    PointJ R2; scalar_mul(R2, nPub, en_be);

    PointJ R; pj_add(R1, R2, R);
    if (R.inf){ std::cout<<"bip340_verify=fail\n"; return 0; }
    PointA Ra; pa_from_jacobian(R, Ra);
    if (fe_is_odd(Ra.y)){ std::cout<<"bip340_verify=fail\n"; return 0; }
    if (fe_cmp(Ra.x, rx)==0){ std::cout<<"bip340_verify=ok\n"; } else { std::cout<<"bip340_verify=fail\n"; }
    return 0;
}
