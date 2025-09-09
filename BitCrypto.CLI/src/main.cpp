#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/field_n.h>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/sha512.h>
#include <bitcrypto/hash/hmac_sha512.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/encoding/base58.h>
#include <bitcrypto/encoding/b58check.h>
#include <bitcrypto/encoding/taproot.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/rng/rng.h>
#include <bitcrypto/kdf/pbkdf2_hmac_sha512.h>
#include <bitcrypto/hd/bip32.h>
#include <bitcrypto/hd/bip39.h>
#include <bitcrypto/hd/bip44.h>

using namespace bitcrypto;

static bool hex_to_bytes(const std::string& s, std::vector<uint8_t>& out){
    if (s.size()%2) return false; out.resize(s.size()/2);
    auto hv=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+c-'a'; if(c>='A'&&c<='F')return 10+c-'A'; return -1; };
    for (size_t i=0;i<s.size();i+=2){
        int hi=hv(s[i]), lo=hv(s[i+1]); if (hi<0||lo<0) return false; out[i/2]=(uint8_t)((hi<<4)|lo);
    } return true;
}
static std::string bytes_to_hex(const uint8_t* p,size_t n){ std::ostringstream o; o<<std::hex<<std::setfill('0'); for(size_t i=0;i<n;i++) o<<std::setw(2)<<(int)p[i]; return o.str(); }

static void print_help(){
    std::cout<<
R"(BitCrypto.CLI
EC-ASSINATURA:
  --sign-ecdsa --priv <hex32> --msg32 <hex32>
  --verify-ecdsa --pub <hex33|65> --sig <DERhex> --msg32 <hex32>
  --sign-schnorr --priv <hex32> --msg32 <hex32> [--aux <hex32>]
  --verify-schnorr --xonly <hex32> --sig <hex64> --msg32 <hex32>

HD (BIP-39/32/44):
  --mnemonic --strength <128|160|192|224|256> [--pass <pass>]
  --seed --mnemonic-phrase "<palavras...>" [--pass <pass>]
  --xprv-from-seed <seedhex> [--testnet]
  --derive "m/.../..." (--xprv-from-seed <seedhex> | --xprv <base58>) [--testnet]
  --xpub-from-xprv <base58-xprv>
  --derive-pub "m/.../..." --xpub <base58-xpub> [--testnet]

Notas:
- Wordlist BIP-39 atual em resources/bip39/english.txt (dev). Substitua pela canônica p/ interoperar.
)"<<std::endl;
}

int main(int argc, char** argv){
    if (argc<=1){ print_help(); return 0; }

    bool sign_ecdsa=false, verify_ecdsa=false, sign_schnorr=false, verify_schnorr=false;
    bool want_mnemonic=false, want_seed=false, want_xprv=false, want_derive=false, want_xpub_from_xprv=false, want_derive_pub=false;
    bool testnet_hd=false;
    std::string msg32_hex, sig_hex, pub_hex, xonly_hex, aux_hex;
    std::string mnemonic, passphrase, seed_hex, xprv_b58, xpub_b58, path_str, xprv_import, xpub_import;
    int strength_bits=128;

    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--sign-ecdsa") sign_ecdsa=true;
        else if (a=="--verify-ecdsa") verify_ecdsa=true;
        else if (a=="--sign-schnorr") sign_schnorr=true;
        else if (a=="--verify-schnorr") verify_schnorr=true;
        else if (a=="--msg32" && i+1<argc) msg32_hex=argv[++i];
        else if (a=="--sig" && i+1<argc) sig_hex=argv[++i];
        else if (a=="--pub" && i+1<argc) pub_hex=argv[++i];
        else if (a=="--xonly" && i+1<argc) xonly_hex=argv[++i];
        else if (a=="--aux" && i+1<argc) aux_hex=argv[++i];

        else if (a=="--mnemonic") want_mnemonic=true;
        else if (a=="--strength" && i+1<argc) strength_bits=std::stoi(argv[++i]);
        else if (a=="--pass" && i+1<argc) passphrase=argv[++i];
        else if (a=="--seed") want_seed=true;
        else if (a=="--mnemonic-phrase" && i+1<argc) mnemonic=argv[++i];
        else if (a=="--xprv-from-seed" && i+1<argc) { seed_hex=argv[++i]; want_xprv=true; }
        else if (a=="--derive" && i+1<argc) { path_str=argv[++i]; want_derive=true; }
        else if (a=="--xprv" && i+1<argc) xprv_import=argv[++i];
        else if (a=="--xpub-from-xprv" && i+1<argc) { xprv_b58=argv[++i]; want_xpub_from_xprv=true; }
        else if (a=="--derive-pub" && i+1<argc) { path_str=argv[++i]; want_derive_pub=true; }
        else if (a=="--xpub" && i+1<argc) xpub_import=argv[++i];
        else if (a=="--testnet") testnet_hd=true;
        else if (a=="--help") { print_help(); return 0; }
        else { std::cerr<<"Arg desconhecido: "<<a<<"\n"; return 1; }
    }

    auto to_bytes = [](const std::string& h)->std::vector<uint8_t>{ std::vector<uint8_t> v; hex_to_bytes(h,v); return v; };

    // ---- Assinaturas ----
    if (sign_ecdsa || verify_ecdsa || sign_schnorr || verify_schnorr){
        if (msg32_hex.size()!=64){ std::cerr<<"--msg32 requer 32 bytes hex\n"; return 1; }
        std::vector<uint8_t> m=to_bytes(msg32_hex);

        if (sign_ecdsa){
            if (seed_hex.empty() && xprv_import.empty() && pub_hex.empty()){
                // requires --priv
            }
        }

        if (sign_ecdsa){
            std::string priv_hex; // expect via --priv
            for (int i=1;i<argc;i++){ if (std::string(argv[i])=="--priv" && i+1<argc){ priv_hex=argv[i+1]; break; } }
            if (priv_hex.size()!=64){ std::cerr<<"--priv <hex32> é obrigatório para --sign-ecdsa\n"; return 1; }
            auto d=to_bytes(priv_hex); bitcrypto::sign::ECDSA_Signature sig{};
            if (!bitcrypto::sign::ecdsa_sign_rfc6979(d.data(), m.data(), sig)){ std::cerr<<"Falha ECDSA\n"; return 1; }
            auto der = bitcrypto::sign::der_from_rs(sig.r, sig.s);
            std::cout<<bytes_to_hex(der.data(), der.size())<<"\n"; return 0;
        }
        if (verify_ecdsa){
            if (pub_hex.empty() || sig_hex.empty()){ std::cerr<<"--pub <hex33|65> e --sig <DERhex>\n"; return 1; }
            std::vector<uint8_t> Q; if (!hex_to_bytes(pub_hex, Q) || (Q.size()!=33 && Q.size()!=65)){ std::cerr<<"--pub inválido\n"; return 1; }
            std::vector<uint8_t> der; if (!hex_to_bytes(sig_hex, der)){ std::cerr<<"--sig inválido\n"; return 1; }
            uint8_t r[32], s[32]; if (!bitcrypto::sign::der_to_rs(der, r, s)){ std::cerr<<"DER inválido/estrito\n"; return 1; }
            bitcrypto::sign::ECDSA_Signature sg; std::memcpy(sg.r,r,32); std::memcpy(sg.s,s,32);
            bool ok = bitcrypto::sign::ecdsa_verify(Q.data(), Q.size(), m.data(), sg);
            std::cout<<(ok?"OK":"FAIL")<<"\n"; return ok?0:1;
        }
        if (sign_schnorr){
            std::string priv_hex; for (int i=1;i<argc;i++){ if (std::string(argv[i])=="--priv" && i+1<argc){ priv_hex=argv[i+1]; break; } }
            if (priv_hex.size()!=64){ std::cerr<<"--priv <hex32> é obrigatório\n"; return 1; }
            auto d=to_bytes(priv_hex); uint8_t aux[32]; bool use_aux=false;
            if (!aux_hex.empty()){ auto a=to_bytes(aux_hex); if (a.size()!=32){ std::cerr<<"--aux inválido\n"; return 1; } std::memcpy(aux,a.data(),32); use_aux=true; }
            uint8_t sig64[64];
            if (!bitcrypto::sign::schnorr_sign_bip340(d.data(), m.data(), sig64, use_aux?aux:nullptr)){ std::cerr<<"Falha Schnorr\n"; return 1; }
            std::cout<<bytes_to_hex(sig64, 64)<<"\n"; return 0;
        }
        if (verify_schnorr){
            if (xonly_hex.size()!=64 || sig_hex.size()!=128){ std::cerr<<"--xonly <hex32> e --sig <hex64>\n"; return 1; }
            auto X=to_bytes(xonly_hex); auto S=to_bytes(sig_hex);
            bool ok = bitcrypto::sign::schnorr_verify_bip340(X.data(), m.data(), S.data());
            std::cout<<(ok?"OK":"FAIL")<<"\n"; return ok?0:1;
        }
    }

    // ---- HD Wallet ----
    if (want_mnemonic){
        if (!(strength_bits==128||strength_bits==160||strength_bits==192||strength_bits==224||strength_bits==256)){
            std::cerr<<"--strength inválido\n"; return 1;
        }
        std::vector<uint8_t> ent(strength_bits/8);
        if (!bitcrypto::rng::random_bytes(ent.data(), ent.size())){ std::cerr<<"Falha RNG (CNG)\n"; return 1; }
        // Carrega wordlist dev
        std::ifstream wf("resources/bip39/english.txt"); if (!wf){ std::cerr<<"resources/bip39/english.txt não encontrado\n"; return 1; }
        std::vector<std::string> lines; std::string line; while (std::getline(wf,line)) if(!line.empty()) lines.push_back(line);
        std::vector<std::string> wl; if (!bitcrypto::hd::load_wordlist(lines, wl)){ std::cerr<<"Wordlist inválida\n"; return 1; }
        std::string phrase; if (!bitcrypto::hd::entropy_to_mnemonic(ent.data(), ent.size(), wl, phrase)){ std::cerr<<"Falha BIP39\n"; return 1; }
        std::cout<<phrase<<"\n"; return 0;
    }
    if (want_seed){
        if (mnemonic.empty()){ std::cerr<<"--mnemonic-phrase requerido\n"; return 1; }
        uint8_t seed[64]; bitcrypto::hd::bip39_seed_from_mnemonic(mnemonic, passphrase, seed);
        std::cout<<bytes_to_hex(seed, 64)<<"\n"; return 0;
    }
    if (want_xprv){
        std::vector<uint8_t> seed; if (!hex_to_bytes(seed_hex, seed)){ std::cerr<<"--xprv-from-seed exige seed hex\n"; return 1; }
        bitcrypto::hd::ExtPriv m; if (!bitcrypto::hd::master_from_seed(seed.data(), seed.size(), m)){ std::cerr<<"master_from_seed falhou\n"; return 1; }
        auto net = testnet_hd ? bitcrypto::hd::Network::TEST : bitcrypto::hd::Network::MAIN;
        std::cout<<bitcrypto::hd::to_base58_xprv(m, net)<<"\n"; return 0;
    }
    if (want_derive){
        bitcrypto::hd::ExtPriv node{}; bool have_node=false; auto net = testnet_hd ? bitcrypto::hd::Network::TEST : bitcrypto::hd::Network::MAIN;
        if (!xprv_import.empty()){
            if (!bitcrypto::hd::from_base58_xprv(xprv_import, node, net)){ std::cerr<<"xprv inválido\n"; return 1; }
            have_node=true;
        } else if (!seed_hex.empty()){
            std::vector<uint8_t> seed; if (!hex_to_bytes(seed_hex, seed)){ std::cerr<<"seed hex inválido\n"; return 1; }
            if (!bitcrypto::hd::master_from_seed(seed.data(), seed.size(), node)){ std::cerr<<"master_from_seed falhou\n"; return 1; }
            have_node=true;
        }
        if (!have_node){ std::cerr<<"Forneça --xprv <base58> ou --xprv-from-seed <seedhex>\n"; return 1; }
        std::vector<uint32_t> elems; if (!bitcrypto::hd::parse_bip44_path(path_str, elems)){ std::cerr<<"caminho inválido\n"; return 1; }
        for (auto idx : elems){
            bitcrypto::hd::ExtPriv child; if (!bitcrypto::hd::ckd_priv(node, idx, child)){ std::cerr<<"ckd_priv falhou em "<<idx<<"\n"; return 1; }
            node = child;
        }
        std::cout<<bitcrypto::hd::to_base58_xprv(node, net)<<"\n"; return 0;
    }
    if (want_xpub_from_xprv){
        bitcrypto::hd::ExtPriv xp{}; auto net=bitcrypto::hd::Network::MAIN;
        if (!bitcrypto::hd::from_base58_xprv(xprv_b58, xp, net)){ std::cerr<<"xprv inválido\n"; return 1; }
        bitcrypto::hd::ExtPub pb{}; if (!bitcrypto::hd::neuter(xp, pb)){ std::cerr<<"neuter falhou\n"; return 1; }
        std::cout<<bitcrypto::hd::to_base58_xpub(pb, net)<<"\n"; return 0;
    }
    if (want_derive_pub){
        bitcrypto::hd::ExtPub xp{}; auto net=bitcrypto::hd::Network::MAIN;
        if (!bitcrypto::hd::from_base58_xpub(xpub_import, xp, net)){ std::cerr<<"xpub inválido\n"; return 1; }
        std::vector<uint32_t> elems; if (!bitcrypto::hd::parse_bip44_path(path_str, elems)){ std::cerr<<"caminho inválido\n"; return 1; }
        for (auto idx : elems){
            if (idx & 0x80000000U){ std::cerr<<"caminho possui hardened; não suportado em xpub\n"; return 1; }
            bitcrypto::hd::ExtPub child; if (!bitcrypto::hd::ckd_pub(xp, idx, child)){ std::cerr<<"ckd_pub falhou em "<<idx<<"\n"; return 1; }
            xp = child;
        }
        std::cout<<bitcrypto::hd::to_base58_xpub(xp, net)<<"\n"; return 0;
    }

    print_help();
    return 0;
}
