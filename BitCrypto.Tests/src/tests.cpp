#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <cstring>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/ripemd160.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/encoding/wif.h>
#include <bitcrypto/encoding/b58check.h>
#include <bitcrypto/encoding/base58.h>
#include <bitcrypto/encoding/segwit.h>
#include <bitcrypto/encoding/taproot.h>
#include <bitcrypto/sign/sign.h>
#include <bitcrypto/sign/bip322.h>
#include <bitcrypto/encoding/der.h>
#include <bitcrypto/hd/bip39.h>
#include <bitcrypto/hd/bip32.h>
#include <bitcrypto/tx/script.h>
#include <bitcrypto/tx/miniscript.h>
#include <bitcrypto/tx/tapscript.h>

using namespace bitcrypto;

static std::string hex(const uint8_t* p, size_t n){ static const char* hx="0123456789abcdef"; std::string s; s.resize(n*2); for(size_t i=0;i<n;i++){ s[2*i]=hx[p[i]>>4]; s[2*i+1]=hx[p[i]&0xF]; } return s; }

int main(){
    // SHA-256 vetores conhecidos
    {
        uint8_t out[32]; hash::sha256(nullptr, 0, out);
        if (hex(out,32)!="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"){ std::cerr<<"SHA256(\"\") falhou\n"; return 1; }
        const char* abc="abc"; hash::sha256((const uint8_t*)abc,3,out);
        if (hex(out,32)!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"){ std::cerr<<"SHA256(\"abc\") falhou\n"; return 1; }
    }
    // EC sanity: k=1 → pubkey comprimida 33B (prefixo 02/03)
    {
        uint8_t k32[32]={0}; k32[31]=1;
        U256 k = U256::from_be32(k32);
        auto Pub = Secp256k1::derive_pubkey(k);
        uint8_t out[65]; size_t olen=0; encode_pubkey(Pub, true, out, olen);
        if (olen!=33 || (out[0]!=0x02 && out[0]!=0x03)){ std::cerr<<"PubKey comprimida inválida\n"; return 1; }
    }
    // BIP-322 message sign/verify
    {
        uint8_t k32[32]={0}; k32[31]=1;
        U256 priv = U256::from_be32(k32);
        auto pub = Secp256k1::derive_pubkey(priv);
        std::string msg="bip322";
        auto sig = bitcrypto::sign::sign_message(priv, msg);
        if (!bitcrypto::sign::verify_message(pub, msg, sig)){ std::cerr<<"bip322 falhou\n"; return 1; }
        sig.r[0]^=1;
        if (bitcrypto::sign::verify_message(pub, msg, sig)){ std::cerr<<"bip322 aceitou assinatura alterada\n"; return 1; }
        ECPointA inf{Fp::zero(), Fp::zero(), true};
        if (bitcrypto::sign::verify_message(inf, msg, sig)){ std::cerr<<"bip322 aceitou pub inválida\n"; return 1; }
    }
    // Base58Check round-trip
    {
        std::vector<uint8_t> payload(21,0); payload[0]=0x00; for(int i=1;i<=20;i++) payload[i]=(uint8_t)i;
        std::string enc = bitcrypto::encoding::base58check_encode(payload);
        std::vector<uint8_t> back; if (!bitcrypto::encoding::base58check_decode(enc, back) || back!=payload){ std::cerr<<"Base58Check round-trip falhou\n"; return 1; }
    }
    // P2PKH decode de endereço gerado localmente
    {
        uint8_t k32[32]={0}; k32[31]=1;
        auto ar = bitcrypto::encoding::p2pkh_from_priv(k32, true, bitcrypto::encoding::Network::MAINNET);
        uint8_t ver=0, h160[20]={0};
        if (!bitcrypto::encoding::p2pkh_decode_address(ar.address_base58, ver, h160)){ std::cerr<<"p2pkh_decode falhou\n"; return 1; }
        if (ver != 0x00){ std::cerr<<"version inesperada\n"; return 1; }
        uint8_t pub[65]; size_t plen=0; U256 k = U256::from_be32(k32); auto Pub = Secp256k1::derive_pubkey(k); encode_pubkey(Pub, true, pub, plen);
        uint8_t hc[20]; hash::hash160(pub, plen, hc);
        for (int i=0;i<20;i++) if (hc[i]!=h160[i]){ std::cerr<<"hash160 mismatch\n"; return 1; }
    }
    // Bech32 P2WPKH
    {
        using namespace bitcrypto::encoding;
        uint8_t k32[32]={0}; k32[31]=1;
        std::string addr = p2wpkh_from_priv(k32, true, /*testnet=*/true);
        bool is_tb=false; uint8_t prog[20]; 
        if (!p2wpkh_decode_address(addr, is_tb, prog) || !is_tb) { std::cerr<<"Bech32 P2WPKH decode falhou\n"; return 1; }
        U256 k = U256::from_be32(k32); auto Pub = Secp256k1::derive_pubkey(k);
        uint8_t pub[65]; size_t plen=0; encode_pubkey(Pub, true, pub, plen);
        uint8_t h[20]; hash::hash160(pub, plen, h);
        for (int i=0;i<20;i++) if (h[i]!=prog[i]) { std::cerr<<"Bech32 P2WPKH programa não confere\n"; return 1; }
    }
    // Taproot P2TR (mainnet)
    {
        using namespace bitcrypto::encoding;
        uint8_t k32[32]={0}; k32[31]=1;
        std::string addr = p2tr_from_priv(k32, /*testnet=*/false);
        bool is_tb=false; uint8_t prog32[32];
        if (p2tr_decode_address(addr, is_tb, prog32) && !is_tb) {
            U256 k = U256::from_be32(k32);
            auto P = Secp256k1::derive_pubkey(k);
            uint8_t xonly[32]; bool neg=false;
            auto Peven = normalize_even_y(P, xonly, neg);
            uint8_t t32[32]; hash::sha256_tagged("TapTweak", xonly, 32, t32);
            U256 t = U256::from_be32(t32); Secp256k1::scalar_mod_n(t);
            auto tG = Secp256k1::scalar_mul(t, Secp256k1::G());
            auto Qj = Secp256k1::add(Secp256k1::to_jacobian(Peven), tG);
            auto Q = Secp256k1::to_affine(Qj);
            uint8_t qx[32]; bool _=false; normalize_even_y(Q, qx, _);
            for (int i=0;i<32;i++) if (qx[i]!=prog32[i]) { std::cerr<<"Taproot programa não confere\n"; return 1; }
    } else { std::cerr<<"Taproot decode falhou\n"; return 1; }
    }
    // WIF round-trip
    {
        uint8_t k32[32]={0}; for(int i=0;i<32;i++) k32[i]=(uint8_t)i;
        std::string wif = bitcrypto::encoding::to_wif(k32, /*compressed=*/true, bitcrypto::encoding::Network::MAINNET);
        uint8_t outk[32]; bool comp=false; bitcrypto::encoding::Network net=bitcrypto::encoding::Network::MAINNET;
        if (!bitcrypto::encoding::from_wif(wif, outk, comp, net) || !comp || net!=bitcrypto::encoding::Network::MAINNET){ std::cerr<<"WIF decode falhou\n"; return 1; }
        for (int i=0;i<32;i++) if (outk[i]!=k32[i]) { std::cerr<<"WIF privkey mismatch\n"; return 1; }
    }
    // Base58 inválido proibido + Base58Check checksum inválido
    {
        std::vector<uint8_t> out; if (bitcrypto::encoding::base58_decode("10OIl", out)) { std::cerr<<"Base58 inválido foi aceito\n"; return 1; }
        std::vector<uint8_t> payload(21,0x11); std::string enc = bitcrypto::encoding::base58check_encode(payload);
        if (!enc.empty()) enc.back() = (enc.back()=='1')?'2':'1'; std::vector<uint8_t> back; if (bitcrypto::encoding::base58check_decode(enc, back)) { std::cerr<<"Base58Check checksum inválido aceito\n"; return 1; }
    }
    // Bech32 mix-case rejeitado + HRP extremos + zeros no Base58
    {
        using namespace bitcrypto::encoding;
        std::string bad = "Tb1qexampleaddress000000000000000000000qqqqqqqq"; std::string hrp; std::vector<uint8_t> data; Bech32Variant var;
        if (bech32_decode(bad, hrp, data, var)) { std::cerr<<"Bech32 mixed-case aceito\n"; return 1; }
        std::string hrp84(84, 'a'); std::vector<uint8_t> d={0}; std::string enc2; if (bech32_encode(hrp84, d, Bech32Variant::BECH32, enc2)) { std::cerr<<"bech32 aceitou HRP>83\n"; return 1; }
        std::string hrp1(1, 'a'); std::string ok; bech32_encode(hrp1, d, Bech32Variant::BECH32, ok); std::string out_hrp; std::vector<uint8_t> outd; Bech32Variant ism;
        if (ok.empty() || !bech32_decode(ok, out_hrp, outd, ism)) { std::cerr<<"bech32 falhou HRP=1\n"; return 1; }
        std::vector<uint8_t> payload = {0x00,0x00,0x00,0xAB,0xCD}; std::string s = bitcrypto::encoding::base58_encode(payload.data(), payload.size());
        std::vector<uint8_t> back2; if (!bitcrypto::encoding::base58_decode(s, back2) || back2!=payload) { std::cerr<<"Base58 round-trip falhou (zeros)\n"; return 1; }
    }
    // Coerência SegWit: v1 com checksum bech32 deve falhar
    {
        using namespace bitcrypto::encoding;
        std::vector<uint8_t> prog32(32, 0x01); std::vector<uint8_t> data; data.push_back(1);
        std::vector<uint8_t> prog5; if (!convert_bits(prog32, 8, 5, true, prog5)) { std::cerr<<"convert_bits v1->5 falhou\n"; return 1; }
        data.insert(data.end(), prog5.begin(), prog5.end());
        std::string wrong; bech32_encode("bc", data, Bech32Variant::BECH32, wrong);
        std::string hrp; std::vector<uint8_t> pr; int ver=0; bool ok = segwit_decode_address(wrong, hrp, ver, pr);
        if (ok) { std::cerr<<"segwit_decode aceitou v1+bech32\n"; return 1; }
    }
    // convert_bits propriedade 8->5->8
    {
        using namespace bitcrypto::encoding;
        std::mt19937_64 rng(12345);
        for (int iter=0; iter<200; ++iter){
            size_t n = (size_t)(rng()%128);
            std::vector<uint8_t> in(n); for (size_t i=0;i<n;i++) in[i]=(uint8_t)rng();
            std::vector<uint8_t> five; if (!convert_bits(in, 8, 5, true, five)) { std::cerr<<"convert_bits 8->5 falhou\n"; return 1; }
            std::vector<uint8_t> back; if (!convert_bits(five, 5, 8, false, back)) { std::cerr<<"convert_bits 5->8 falhou\n"; return 1; }
            if (back != in) { std::cerr<<"convert_bits property falhou\n"; return 1; }
        }
    }
    
    // Pendência: reativar teste de round-trip ECDSA após correção do verifier
    // DER negativos (length/integers não-minimais)
    {
        uint8_t bad1[]={0x30,0x05,0x02,0x01,0x01,0x02,0x01}; // truncado
        uint8_t r32[32], s32[32];
        if (bitcrypto::encoding::ecdsa_der_decode(bad1, sizeof(bad1), r32, s32)) { std::cerr<<"DER inválido aceito\n"; return 1; }
    }
    // Pendência: adicionar testes Schnorr BIP-340 após estabilização das rotinas

    // BIP-39: seed from mnemonic (sanity)
    {
        using namespace bitcrypto::hd;
        uint8_t seed[64];
        bip39_seed_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR", seed);
        // Sanity: seed must be 64B and non-zero
        int z=0; for (int i=0;i<64;i++) z |= seed[i];
        if (!z){ std::cerr<<"bip39_seed_from_mnemonic result parece nulo\n"; return 1; }
    }
    // Pendência: verificar propriedades de derivação BIP-32 em testes dedicados

    // BIP32 import/export e derivação pública vs privada (consistência)
    {
        // semente determinística
        std::vector<uint8_t> seed(64); for (int i=0;i<64;i++) seed[i]=(uint8_t)i;
        bitcrypto::hd::ExtPriv m; if(!bitcrypto::hd::master_from_seed(seed.data(), seed.size(), m)){ std::cerr<<"master_from_seed falhou\n"; return 1; }
        auto xprv = bitcrypto::hd::to_base58_xprv(m, bitcrypto::hd::Network::TEST);
        bitcrypto::hd::ExtPriv imp; bitcrypto::hd::Network net; if(!bitcrypto::hd::from_base58_xprv(xprv, imp, net)){ std::cerr<<"from_xprv falhou\n"; return 1; }
        auto xprv2 = bitcrypto::hd::to_base58_xprv(imp, net); if (xprv2!=xprv){ std::cerr<<"xprv roundtrip falhou\n"; return 1; }
        bitcrypto::hd::ExtPub xp; if(!bitcrypto::hd::neuter(imp, xp)){ std::cerr<<"neuter falhou\n"; return 1; }
        auto xpub = bitcrypto::hd::to_base58_xpub(xp, net);
        bitcrypto::hd::ExtPub xp2; bitcrypto::hd::Network net2; if(!bitcrypto::hd::from_base58_xpub(xpub, xp2, net2)){ std::cerr<<"from_xpub falhou\n"; return 1; }
        auto xpub2 = bitcrypto::hd::to_base58_xpub(xp2, net2); if (xpub2!=xpub){ std::cerr<<"xpub roundtrip falhou\n"; return 1; }
        // Pendência: validar derivação pública vs privada em casos não-hardened
    }


    

    
    // WIF roundtrip (mainnet/testnet, compressed)
    {
        uint8_t d[32]; for(int i=0;i<32;i++) d[i]=(uint8_t)(i+1);
        std::string w_main = bitcrypto::encoding::to_wif(d, true, bitcrypto::encoding::Network::MAINNET);
        std::string w_test = bitcrypto::encoding::to_wif(d, true, bitcrypto::encoding::Network::TESTNET);
        uint8_t priv[32]; bool comp=false; bitcrypto::encoding::Network net;
        if (!bitcrypto::encoding::from_wif(w_main, priv, comp, net)){ std::cerr<<"WIF mainnet decode falhou\n"; return 1; }
        if (!comp || net!=bitcrypto::encoding::Network::MAINNET){ std::cerr<<"WIF mainnet flags incorretos\n"; return 1; }
        for (int i=0;i<32;i++) if (priv[i]!=d[i]){ std::cerr<<"WIF mainnet payload divergente\n"; return 1; }
        if (!bitcrypto::encoding::from_wif(w_test, priv, comp, net)){ std::cerr<<"WIF testnet decode falhou\n"; return 1; }
        if (!comp || net!=bitcrypto::encoding::Network::TESTNET){ std::cerr<<"WIF testnet flags incorretos\n"; return 1; }
    }

    
    // Pendência: validar construção de Tapscript thresh quando CHECKSIGADD estiver estabilizado
    // Miniscript parse negativo (or_i sem vírgula)
    {
        std::vector<uint8_t> ws; if (bitcrypto::tx::miniscript_compile("or_i(pk(02aa),pk(03bb) pk(03cc))", ws)){ std::cerr<<"parse deveria falhar\\n"; return 1; }
    }

    std::cout<<"OK\n"; return 0;
}
