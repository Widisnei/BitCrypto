#include <iostream>
#include <vector>
#include <string>
#include <random>
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
#include <bitcrypto/psbt2/psbt_v2.h>
#include <bitcrypto/psbt2/psbt_v2_sign.h>
#include <bitcrypto/scripts/descriptor.h>

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
        std::string bad = "Tb1qexampleaddress000000000000000000000qqqqqqqq"; std::string hrp; std::vector<uint8_t> data; bool is_m=false;
        if (bech32_decode(bad, hrp, data, is_m)) { std::cerr<<"Bech32 mixed-case aceito\n"; return 1; }
        std::string hrp84(84, 'a'); std::vector<uint8_t> d={0}; std::string enc2 = bech32_encode(hrp84, d, false); if (!enc2.empty()) { std::cerr<<"bech32 aceitou HRP>83\n"; return 1; }
        std::string hrp1(1, 'a'); std::string ok = bech32_encode(hrp1, d, false); std::string out_hrp; std::vector<uint8_t> outd; bool ism=false;
        if (ok.empty() || !bech32_decode(ok, out_hrp, outd, ism)) { std::cerr<<"bech32 falhou HRP=1\n"; return 1; }
        std::vector<uint8_t> payload = {0x00,0x00,0x00,0xAB,0xCD}; std::string s = bitcrypto::encoding::base58_encode(payload.data(), payload.size());
        std::vector<uint8_t> back2; if (!bitcrypto::encoding::base58_decode(s, back2) || back2!=payload) { std::cerr<<"Base58 round-trip falhou (zeros)\n"; return 1; }
    }
    // Coerência SegWit: v1 com checksum bech32 deve falhar
    {
        using namespace bitcrypto::encoding;
        std::vector<uint8_t> prog32(32, 0x01); std::vector<uint8_t> data; data.push_back(1);
        std::vector<uint8_t> prog5; if (!convert_bits(prog5, 5, prog32, 8, true)) { std::cerr<<"convert_bits v1->5 falhou\n"; return 1; }
        data.insert(data.end(), prog5.begin(), prog5.end());
        std::string wrong = bech32_encode("bc", data, /*bech32m=*/false);
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
            std::vector<uint8_t> five; if (!convert_bits(five, 5, in, 8, true)) { std::cerr<<"convert_bits 8->5 falhou\n"; return 1; }
            std::vector<uint8_t> back; if (!convert_bits(back, 8, five, 5, false)) { std::cerr<<"convert_bits 5->8 falhou\n"; return 1; }
            if (back != in) { std::cerr<<"convert_bits property falhou\n"; return 1; }
        }
    }
    
    // ECDSA sign/verify round-trip
    {
        uint8_t d32[32]={0}; d32[31]=1;
        uint8_t m32[32]; for(int i=0;i<32;i++) m32[i]=(uint8_t)(i*3+1);
        std::vector<uint8_t> der;
        if (!bitcrypto::sign::ecdsa_sign(d32, m32, der)){ std::cerr<<"ECDSA sign falhou\n"; return 1; }
        // obter pubkey
        bitcrypto::U256 k = bitcrypto::U256::from_be32(d32);
        auto Pub = bitcrypto::Secp256k1::derive_pubkey(k);
        uint8_t pub[65]; size_t plen=0; bitcrypto::encode_pubkey(Pub, true, pub, plen);
        if (!bitcrypto::sign::ecdsa_verify(pub, plen, m32, der.data(), der.size())){ std::cerr<<"ECDSA verify falhou\n"; return 1; }
        // mensagem alterada → deve falhar
        m32[0]^=0xFF;
        if (bitcrypto::sign::ecdsa_verify(pub, plen, m32, der.data(), der.size())){ std::cerr<<"ECDSA verify aceitou msg alterada\n"; return 1; }
    }
    // DER negativos (length/integers não-minimais)
    {
        uint8_t bad1[]={0x30,0x05,0x02,0x01,0x01,0x02,0x01}; // truncado
        uint8_t z[32]={0};
        uint8_t pub[33]={0}; // dummy; verificação falhará na DER antes
        if (bitcrypto::sign::ecdsa_verify(pub, sizeof(pub), z, bad1, sizeof(bad1))) { std::cerr<<"DER inválido aceito\n"; return 1; }
    }
    // Schnorr BIP-340 sign/verify
    {
        uint8_t d32[32]={0}; d32[31]=1;
        uint8_t m32[32]={0}; // mensagem zero
        uint8_t sig[64];
        if (!bitcrypto::sign::schnorr_sign(d32, m32, sig)){ std::cerr<<"Schnorr sign falhou\n"; return 1; }
        // pub x-only
        bitcrypto::U256 k = bitcrypto::U256::from_be32(d32);
        auto Pub = bitcrypto::Secp256k1::derive_pubkey(k);
        uint8_t pubc[33]; size_t plen=0; bitcrypto::encode_pubkey(Pub, true, pubc, plen);
        bool ok = bitcrypto::sign::schnorr_verify(pubc, plen, m32, sig);
        if (!ok){ std::cerr<<"Schnorr verify falhou\n"; return 1; }
        // Mensagem alterada → deve falhar
        m32[0]=1;
        if (bitcrypto::sign::schnorr_verify(pubc, plen, m32, sig)){ std::cerr<<"Schnorr verify aceitou msg alterada\n"; return 1; }
    }

    // BIP-39: seed from mnemonic (sanity)
    {
        using namespace bitcrypto::hd;
        uint8_t seed[64];
        bip39_seed_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR", seed);
        // Sanity: seed must be 64B and non-zero
        int z=0; for (int i=0;i<64;i++) z |= seed[i];
        if (!z){ std::cerr<<"bip39_seed_from_mnemonic result parece nulo\n"; return 1; }
    }
    // BIP-32 properties: CKDpub(CKDpriv(m,i),j) == CKDpub(CKDpub(M,i),j) para i,j não-hardened
    {
        using namespace bitcrypto; using namespace bitcrypto::hd;
        // master from fixed seed (SHA256 of string)
        const char* seed_str="test-seed";
        uint8_t h[32]; bitcrypto::hash::sha256((const uint8_t*)seed_str, (size_t)std::strlen(seed_str), h);
        auto m = master_from_seed(h, 32, NetworkKind::TEST);
        auto M = neuter(m);
        uint8_t fp[4]; fingerprint_from_pub(M, fp); std::memcpy(m.fingerprint, fp, 4); std::memcpy(M.fingerprint, fp, 4);
        XPrv mi; if(!ckd_priv(m, 1, mi)){ std::cerr<<"ckd_priv falhou\n"; return 1; }
        XPrv mij; if(!ckd_priv(mi, 2, mij)){ std::cerr<<"ckd_priv falhou (2)\n"; return 1; }
        XPub Mi; if(!ckd_pub(M, 1, Mi)){ std::cerr<<"ckd_pub falhou\n"; return 1; }
        XPub Mij; if(!ckd_pub(Mi, 2, Mij)){ std::cerr<<"ckd_pub falhou (2)\n"; return 1; }
        // neuter(mij) deve ser igual a Mij (mesma pub/compress, depth e child)
        auto mij_pub = neuter(mij);
        bool eq = (std::memcmp(mij_pub.pub, Mij.pub, 33)==0) && (mij_pub.depth==Mij.depth) && (mij_pub.child==Mij.child);
        if (!eq){ std::cerr<<"BIP-32 propriedade falhou (neuter(mij) != Mij)\n"; return 1; }
    }

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
        // Derivação pública vs privada (não-hardened)
        bitcrypto::hd::ExtPriv d1; if(!bitcrypto::hd::ckd_priv(imp, 1, d1)){ std::cerr<<"ckd_priv 1 falhou\n"; return 1; }
        bitcrypto::hd::ExtPub p1; if(!bitcrypto::hd::ckd_pub(xp2, 1, p1)){ std::cerr<<"ckd_pub 1 falhou\n"; return 1; }
        bitcrypto::hd::ExtPub d1n; if(!bitcrypto::hd::neuter(d1, d1n)){ std::cerr<<"neuter(d1) falhou\n"; return 1; }
        auto a = bitcrypto::hd::to_base58_xpub(p1, net2);
        auto b = bitcrypto::hd::to_base58_xpub(d1n, net2);
        if (a!=b){ std::cerr<<"ckd_pub != neuter(ckd_priv)\n"; return 1; }
    }

    // PSBT/P2WPKH end-to-end (SIGHASH_ALL)
    {
        using namespace bitcrypto;
        using namespace bitcrypto::tx;
        using namespace bitcrypto::psbt;
        using namespace bitcrypto::hash;

        // unsigned tx: 1-in, 1-out
        Tx t; t.version=2; t.locktime=0;
        t.vin.resize(1); t.vin[0].sequence = 0xFFFFFFFD;
        // prevout txid (little-endian em serialização; aqui guardamos o "hash" little)
        for (int i=0;i<32;i++) t.vin[0].prevout.txid[i]=(uint8_t)i;
        t.vin[0].prevout.vout = 1;
        t.vout.resize(1); t.vout[0].value = 5000000000ULL - 10000ULL; // 50 BTC - fee
        // output script (P2WPKH dummy -> OP_0 20 0x11*20)
        t.vout[0].scriptPubKey = {0x00, 0x14}; t.vout[0].scriptPubKey.insert(t.vout[0].scriptPubKey.end(), 20, 0x11);

        Psbt P; P.unsigned_tx = t; P.inputs.resize(1); P.outputs.resize(1);

        // witness UTXO do input 0: valor + scriptPubKey P2WPKH para a nossa chave
        uint8_t d[32]={0}; d[31]=0x01; // priv=1
        U256 du=U256::from_be32(d); Secp256k1::scalar_mod_n(du); auto Q=Secp256k1::derive_pubkey(du); uint8_t pub[65]; size_t plen=0; encode_pubkey(Q,true,pub,plen);
        uint8_t h160[20]; uint8_t tmp[32]; sha256(pub, 33, tmp); ripemd160(tmp, 32, h160);
        std::vector<uint8_t> spk = {0x00, 0x14}; spk.insert(spk.end(), h160, h160+20);
        std::vector<uint8_t> utxo; utxo.reserve(8+1+22); // value + varint(22) + script
        // value
        for (int i=0;i<8;i++) utxo.push_back((uint8_t)((5000000000ULL>>(8*i))&0xFF));
        // script len (22)
        utxo.push_back(22);
        utxo.insert(utxo.end(), spk.begin(), spk.end());
        // add to input map
        std::vector<uint8_t> k{KEY_IN_WITNESS_UTXO};
        P.inputs[0].push_back(MapKV{k,utxo});

        // assina e finaliza
        if (!sign_p2wpkh_input(P, 0, d)){ std::cerr<<"psbt sign falhou\n"; return 1; }
        if (!finalize_p2wpkh(P, 0)){ std::cerr<<"psbt finalize falhou\n"; return 1; }
        // checa witness presente (2 itens: sig+pub)
        if (P.unsigned_tx.vin[0].witness.size()!=2 || P.unsigned_tx.vin[0].witness[1].size()!=33){ std::cerr<<"witness inválida\n"; return 1; }
    }

    // Taproot (P2TR) key-path — PSBT v0 signing/finalization (subset)
    {
        using namespace bitcrypto;
        // d=1
        uint8_t d[32]={0}; d[31]=1;
        // Deriva Q e scriptPubKey P2TR
        auto P = Secp256k1::derive_pubkey(U256::from_be32(d));
        uint8_t px[32]; bool odd=false; tx::xonly_from_point(P, px, odd);
        // Tweak Q = P + H_tweak(Px)*G
        std::vector<uint8_t> msg; msg.insert(msg.end(), px, px+32); uint8_t th[32]; tx::tagged_hash("TapTweak", msg, th);
        auto t = U256::from_be32(th); Secp256k1::scalar_mod_n(t);
        auto Q = Secp256k1::add(Secp256k1::to_jacobian(P), Secp256k1::scalar_mul(t, Secp256k1::G()));
        auto Qa = Secp256k1::to_affine(Q); uint8_t qx[32]; bool qodd=false; tx::xonly_from_point(Qa, qx, qodd);
        // scriptPubKey = OP_1 0x20 <qx>
        std::vector<uint8_t> spk; spk.push_back(0x51); spk.push_back(0x20); spk.insert(spk.end(), qx, qx+32);
        // Cria tx 1-in-1-out
        tx::Transaction txo; txo.version=2; txo.locktime=0; tx::TxIn in; std::memset(in.prevout.txid, 0x11, 32); in.prevout.vout=0; in.sequence=0xFFFFFFFF; txo.vin.push_back(in);
        tx::TxOut o; o.value=40000; o.scriptPubKey = spk; txo.vout.push_back(o);
        // PSBT v0
        psbt::PSBT Psb; Psb.unsigned_tx=txo; Psb.inputs.resize(1); Psb.outputs.resize(1);
        Psb.inputs[0].has_witness_utxo=true; Psb.inputs[0].witness_utxo.value=50000; Psb.inputs[0].witness_utxo.scriptPubKey=spk;
        if (!psbt::sign_psbt(Psb, d)){ std::cerr<<"sign_psbt P2TR falhou\n"; return 1; }
        if (!psbt::finalize_psbt(Psb)){ std::cerr<<"finalize_psbt P2TR falhou\n"; return 1; }
        if (Psb.unsigned_tx.vin[0].witness.size()!=1){ std::cerr<<"witness P2TR deveria ter 1 elemento (assinatura)\n"; return 1; }
        if (Psb.unsigned_tx.vin[0].witness[0].size()!=64 && Psb.unsigned_tx.vin[0].witness[0].size()!=65){ std::cerr<<"assinatura schnorr tamanho inválido\n"; return 1; }
    }

    
    // PSBTv2 P2WPKH bridge sign/final
    {
        using namespace bitcrypto;
        uint8_t d[32]={0}; d[31]=1;
        auto P = Secp256k1::derive_pubkey(U256::from_be32(d)); uint8_t pub[65]; size_t plen=0; encode_pubkey(P,true,pub,plen);
        uint8_t h160[20]; bitcrypto::hash::hash160(pub, plen, h160);
        bitcrypto::tx::Script spk = bitcrypto::tx::Script::p2wpkh(h160);
        // psbt2 create
        bitcrypto::psbt2::PSBT2 P2; P2.tx_version=2;
        bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0x22, 32); I.vout=0; I.sequence=0xFFFFFFFF; I.has_witness_utxo=true; I.witness_utxo.value=50000; I.witness_utxo.scriptPubKey=spk.serialize(); P2.ins.push_back(I);
        bitcrypto::psbt2::Out O; O.amount=40000; O.script=spk.serialize(); P2.outs.push_back(O);
        auto b64=P2.to_base64();
        bitcrypto::psbt2::PSBT2 P2p; if(!bitcrypto::psbt2::PSBT2::from_base64(b64, P2p)){ std::cerr<<"PSBTv2 parse falhou\n"; return 1; }
        bitcrypto::psbt::PSBT P0; if(!P2p.to_psbt_v0(P0)){ std::cerr<<"to_psbt_v0 falhou\n"; return 1; }
        if (!bitcrypto::psbt::sign_psbt(P0, d)){ std::cerr<<"sign_psbt via bridge falhou\n"; return 1; }
        if (!bitcrypto::psbt::finalize_psbt(P0)){ std::cerr<<"finalize falhou\n"; return 1; }
        auto raw = P0.unsigned_tx.serialize();
        if (raw.size()<80){ std::cerr<<"tx v2-p2wpkh pequena\n"; return 1; }
    }
    // PSBTv2 P2TR key-path bridge sign/final
    {
        using namespace bitcrypto;
        uint8_t d[32]={0}; d[31]=1;
        auto P = Secp256k1::derive_pubkey(U256::from_be32(d)); uint8_t px[32]; bool odd=false; tx::xonly_from_point(P, px, odd);
        std::vector<uint8_t> msg; msg.insert(msg.end(), px, px+32); uint8_t th[32]; tx::tagged_hash("TapTweak", msg, th);
        auto t = U256::from_be32(th); Secp256k1::scalar_mod_n(t);
        auto Q = Secp256k1::add(Secp256k1::to_jacobian(P), Secp256k1::scalar_mul(t, Secp256k1::G()));
        auto Qa = Secp256k1::to_affine(Q); uint8_t qx[32]; bool qodd=false; tx::xonly_from_point(Qa, qx, qodd);
        std::vector<uint8_t> spk; spk.push_back(0x51); spk.push_back(0x20); spk.insert(spk.end(), qx, qx+32);
        bitcrypto::psbt2::PSBT2 P2; P2.tx_version=2;
        bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0x33, 32); I.vout=0; I.sequence=0xFFFFFFFF; I.has_witness_utxo=true; I.witness_utxo.value=50000; I.witness_utxo.scriptPubKey=spk; P2.ins.push_back(I);
        bitcrypto::psbt2::Out O; O.amount=40000; O.script=spk; P2.outs.push_back(O);
        bitcrypto::psbt::PSBT P0; if(!P2.to_psbt_v0(P0)){ std::cerr<<"to_psbt_v0 P2TR falhou\n"; return 1; }
        if (!bitcrypto::psbt::sign_psbt(P0, d)){ std::cerr<<"sign_psbt P2TR via bridge falhou\n"; return 1; }
        if (!bitcrypto::psbt::finalize_psbt(P0)){ std::cerr<<"finalize P2TR falhou\n"; return 1; }
        auto raw = P0.unsigned_tx.serialize();
        if (raw.size()<80){ std::cerr<<"tx v2-p2tr pequena\n"; return 1; }
    }

    
    // WIF roundtrip (mainnet/testnet, compressed)
    {
        uint8_t d[32]; for(int i=0;i<32;i++) d[i]=(uint8_t)(i+1);
        std::string w_main = bitcrypto::encoding::to_wif(d, true, bitcrypto::encoding::Network::MAINNET);
        std::string w_test = bitcrypto::encoding::to_wif(d, true, bitcrypto::encoding::Network::TESTNET);
        std::vector<uint8_t> priv; bool comp=false; bool is_test=false;
        if (!bitcrypto::encoding::wif_decode(w_main, priv, comp, is_test)){ std::cerr<<"WIF mainnet decode falhou\n"; return 1; }
        if (priv.size()!=32 || !comp || is_test){ std::cerr<<"WIF mainnet flags/size incorretos\n"; return 1; }
        for (int i=0;i<32;i++) if (priv[i]!=d[i]){ std::cerr<<"WIF mainnet payload divergente\n"; return 1; }
        priv.clear(); comp=false; is_test=false;
        if (!bitcrypto::encoding::wif_decode(w_test, priv, comp, is_test)){ std::cerr<<"WIF testnet decode falhou\n"; return 1; }
        if (priv.size()!=32 || !comp || !is_test){ std::cerr<<"WIF testnet flags/size incorretos\n"; return 1; }
    }
    // PSBTv2 verifier: positivo e negativo (P2SH-P2WSH)
    {
        using namespace bitcrypto;
        uint8_t d1[32]={0}; d1[31]=9; auto P1=Secp256k1::derive_pubkey(U256::from_be32(d1)); uint8_t pub1[65]; size_t l1=0; encode_pubkey(P1,true,pub1,l1);
        std::vector<uint8_t> ws; ws.push_back(0x21); ws.push_back(pub1[0]); for(size_t i=1;i<33;i++) ws.push_back(pub1[i]); ws.push_back(0xAC);
        uint8_t h[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), h);
        std::vector<uint8_t> redeem; redeem.push_back(0x00); redeem.push_back(0x20); redeem.insert(redeem.end(), h, h+32);
        uint8_t rh[20]; bitcrypto::hash::hash160(redeem.data(), redeem.size(), rh);
        std::vector<uint8_t> spk; spk.push_back(0xA9); spk.push_back(0x14); spk.insert(spk.end(), rh, rh+20); spk.push_back(0x87);
        bitcrypto::psbt2::PSBT2 P; P.tx_version=2;
        bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0x33, 32); I.vout=0; I.sequence=0xFFFFFFFE; I.has_witness_utxo=true; I.witness_utxo.value=10000; I.witness_utxo.scriptPubKey=spk; I.has_redeem_script=true; I.redeem_script=redeem; I.has_witness_script=true; I.witness_script=ws;
        P.ins.push_back(I); bitcrypto::psbt2::Out O; O.amount=9000; O.script=spk; P.outs.push_back(O);
        std::string err; if (!bitcrypto::psbt2::verify_psbt2(P, err)){ std::cerr<<"psbt2 verify deveria OK: "<<err<<"\n"; return 1; }
        // negativo
        P.ins[0].redeem_script[3] ^= 0x01;
        if (bitcrypto::psbt2::verify_psbt2(P, err)){ std::cerr<<"psbt2 verify deveria falhar\n"; return 1; }
    }

    
    // Tapscript threshold (thresh) — teste estrutural
    {
        std::string expr = "thresh(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,03c6047f9441ed7d6d3045406e95c07cd85a0dbb43e7e36d09270f09a0e62d249b,02f9308a019258c3107dc7fbd9c0f6a9d5f7f3a4e9d6e3c6e0f6b6c0b8b3d5b1c2)";
        std::vector<uint8_t> ts; if (!bitcrypto::tx::miniscript_compile(expr, ts)){ std::cerr<<"thresh compile falhou\\n"; return 1; }
        if (ts.size()<5 || ts[0]!=0x00 || ts.back()!=0x9C){ std::cerr<<"tapscript thresh formato inesperado\\n"; return 1; }
        int checksig=0, add=0; for (auto b: ts){ if (b==0xAC) checksig++; if (b==0xBA) add++; }
        if (checksig!=1 || add<1){ std::cerr<<"tapscript thresh ops faltando\\n"; return 1; }
        uint8_t leaf[32]; bitcrypto::tx::tapleaf_hash(ts, 0xC0, leaf); bool nz=false; for (int i=0;i<32;i++) nz|=(leaf[i]!=0); if(!nz){ std::cerr<<"tapleaf hash inválido\\n"; return 1; }
    }
    // Miniscript parse negativo (or_i sem vírgula)
    {
        std::vector<uint8_t> ws; if (bitcrypto::tx::miniscript_compile("or_i(pk(02aa),pk(03bb) pk(03cc))", ws)){ std::cerr<<"parse deveria falhar\\n"; return 1; }
    }

    std::cout<<"OK\n"; return 0;
}
