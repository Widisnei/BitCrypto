#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <bitcrypto/hd/bip32.h>
#include <bitcrypto/hd/bip39.h>
#include <bitcrypto/hd/bip44.h>
#include <bitcrypto/rng/rng.h>
#include <bitcrypto/encoding/b58check.h>

static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out){
    if (hex.size()%2) return false; out.resize(hex.size()/2);
    auto h = [](char c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; };
    for (size_t i=0;i<out.size();i++){ int hi=h(hex[2*i]), lo=h(hex[2*i+1]); if(hi<0||lo<0) return false; out[i]=(uint8_t)((hi<<4)|lo); }
    return true;
}
static std::string bytes_to_hex(const uint8_t* p, size_t n){
    static const char* hx="0123456789abcdef"; std::string s; s.resize(n*2);
    for (size_t i=0;i<n;i++){ s[2*i]=hx[(p[i]>>4)&0xF]; s[2*i+1]=hx[p[i]&0xF]; } return s;
}

int main(int argc, char** argv){
    using namespace bitcrypto::hd;
    bool gen_mnemonic=false, seed_from_mnemonic=false, xprv_from_seed=false, xpub_from_xprv=false, derive_xprv=false, derive_xpub=false;
    bool testnet=false;
    std::string wordlist_path, mnemonic, passphrase, seed_hex, xprv_b58, xpub_b58, path_str;
    int strength=128;

    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--mnemonic-gen") gen_mnemonic=true;
        else if (a=="--wordlist" && i+1<argc) wordlist_path=argv[++i];
        else if (a=="--strength" && i+1<argc) strength=std::stoi(argv[++i]);
        else if (a=="--seed-from-mnemonic") seed_from_mnemonic=true;
        else if (a=="--mnemonic" && i+1<argc) mnemonic=argv[++i];
        else if (a=="--pass" && i+1<argc) passphrase=argv[++i];
        else if (a=="--xprv-from-seed" && i+1<argc){ xprv_from_seed=true; seed_hex=argv[++i]; }
        else if (a=="--xpub-from-xprv" && i+1<argc){ xpub_from_xprv=true; xprv_b58=argv[++i]; }
        else if (a=="--derive-xprv" && i+1<argc){ derive_xprv=true; path_str=argv[++i]; }
        else if (a=="--derive-xpub" && i+1<argc){ derive_xpub=true; path_str=argv[++i]; }
        else if (a=="--xpub" && i+1<argc) xpub_b58=argv[++i];
        else if (a=="--testnet") testnet=true;
        else if (a=="--help"){
            std::cout<<"HD CLI:\n"
                     <<"  --mnemonic-gen --wordlist <file> [--strength 128|160|192|224|256]\n"
                     <<"  --seed-from-mnemonic --mnemonic \"w1 w2 ...\" [--pass <str>]\n"
                     <<"  --xprv-from-seed <seed_hex> [--testnet]\n"
                     <<"  --xpub-from-xprv <xprv_base58>\n"
                     <<"  --derive-xprv <path> --xprv-from-seed <seed_hex> [--testnet]\n"
                     <<"  --derive-xpub <path> --xpub <xpub_base58>\n";
            return 0;
        }
    }

    if (gen_mnemonic){
        if (wordlist_path.empty()){ std::cerr<<"--wordlist obrigatório\n"; return 1; }
        std::ifstream wf(wordlist_path); if(!wf){ std::cerr<<"Falha ao abrir wordlist\n"; return 1; }
        std::vector<std::string> wl; std::string line; while (std::getline(wf,line)){ if(!line.empty()) wl.push_back(line); }
        if (wl.size()!=2048){ std::cerr<<"Wordlist inválida\n"; return 1; }
        if (!(strength==128||strength==160||strength==192||strength==224||strength==256)){ std::cerr<<"--strength inválido\n"; return 1; }
        std::vector<uint8_t> ent(strength/8); if (!bitcrypto::rng::random_bytes(ent.data(), ent.size())){ std::cerr<<"RNG falhou\n"; return 1; }
        std::string phrase; if(!mnemonic_generate(ent.data(), ent.size(), wl, phrase)){ std::cerr<<"mnemonic_generate falhou\n"; return 1; }
        std::cout<<phrase<<"\n"; return 0;
    }

    if (seed_from_mnemonic){
        if (mnemonic.empty()){ std::cerr<<"--mnemonic obrigatório\n"; return 1; }
        uint8_t seed[64]; if(!mnemonic_to_seed(mnemonic, passphrase, seed)){ std::cerr<<"mnemonic_to_seed falhou\n"; return 1; }
        std::cout<<bytes_to_hex(seed, 64)<<"\n"; return 0;
    }

    if (xprv_from_seed){
        std::vector<uint8_t> seed; if(!hex_to_bytes(seed_hex, seed)){ std::cerr<<"seed hex inválido\n"; return 1; }
        XPrv m; if(!master_from_seed(seed.data(), seed.size(), m)){ std::cerr<<"master_from_seed falhou\n"; return 1; }
        auto net = testnet ? NetworkB32::TEST : NetworkB32::MAIN;
        std::cout<<xprv_to_base58(m, net)<<"\n"; return 0;
    }

    if (xpub_from_xprv){
        NetworkB32 n; XPrv x; if(!xprv_from_base58(xprv_b58, x, n)){ std::cerr<<"xprv inválido\n"; return 1; }
        XPub p; neuter(x, p);
        std::cout<<xpub_to_base58(p, n)<<"\n"; return 0;
    }

    if (derive_xprv){
        if (path_str.empty() || seed_hex.empty()){ std::cerr<<"--derive-xprv <path> + --xprv-from-seed <seedhex>\n"; return 1; }
        std::vector<uint8_t> seed; if(!hex_to_bytes(seed_hex, seed)){ std::cerr<<"seed hex inválido\n"; return 1; }
        XPrv node; if(!master_from_seed(seed.data(), seed.size(), node)){ std::cerr<<"master_from_seed falhou\n"; return 1; }
        std::vector<uint32_t> path; if(!parse_bip44_path(path_str, path)){ std::cerr<<"path inválido\n"; return 1; }
        for (auto idx : path){ XPrv ch; if(!ckd_priv(node, idx, ch)){ std::cerr<<"ckd_priv falhou\n"; return 1; } node=ch; }
        auto net = testnet ? NetworkB32::TEST : NetworkB32::MAIN;
        std::cout<<xprv_to_base58(node, net)<<"\n"; return 0;
    }

    if (derive_xpub){
        if (path_str.empty() || xpub_b58.empty()){ std::cerr<<"--derive-xpub <path> + --xpub <xpub_b58>\n"; return 1; }
        NetworkB32 n; XPub node; if(!xpub_from_base58(xpub_b58, node, n)){ std::cerr<<"xpub inválido\n"; return 1; }
        std::vector<uint32_t> path; if(!parse_bip44_path(path_str, path)){ std::cerr<<"path inválido\n"; return 1; }
        for (auto idx : path){
            if (idx & 0x80000000u){ std::cerr<<"caminho inclui hardened (não suportado por xpub)\n"; return 1; }
            XPub ch; if(!ckd_pub(node, idx, ch)){ std::cerr<<"ckd_pub falhou\n"; return 1; } node=ch;
        }
        std::cout<<xpub_to_base58(node, n)<<"\n"; return 0;
    }

    std::cerr<<"Use --help para opções.\n"; return 1;
}
