#include <iostream>
#include <vector>
#include <cstring>
#include "../BitCrypto.Core/include/bitcrypto/base.h"
#include "../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
#include "../BitCrypto.Hash/include/bitcrypto/hash/hash160.h"
#include "../BitCrypto.Hash/include/bitcrypto/hash/sha256.h"
#include "../BitCrypto.Tx/include/bitcrypto/tx/tx.h"
#include "../BitCrypto.Tx/include/bitcrypto/tx/miniscript.h"
#include "../BitCrypto.PSBTv2/include/bitcrypto/psbt2/psbt_v2.h"
#include "../BitCrypto.PSBTv2/include/bitcrypto/psbt2/psbt_v2_sign.h"

using namespace bitcrypto;

static std::string hex_of(const uint8_t* p, size_t n){ static const char hx[]="0123456789abcdef"; std::string s; s.resize(n*2); for(size_t i=0;i<n;i++){ s[2*i]=hx[p[i]>>4]; s[2*i+1]=hx[p[i]&0xF]; } return s; }

int main(){
    // P2WSH multisig 2-of-3
    {
        uint8_t d1[32]={0}; d1[31]=1; auto P1=Secp256k1::derive_pubkey(U256::from_be32(d1)); uint8_t pub1[65]; size_t l1=0; encode_pubkey(P1,true,pub1,l1);
        uint8_t d2[32]={0}; d2[31]=2; auto P2=Secp256k1::derive_pubkey(U256::from_be32(d2)); uint8_t pub2[65]; size_t l2=0; encode_pubkey(P2,true,pub2,l2);
        uint8_t d3[32]={0}; d3[31]=3; auto P3=Secp256k1::derive_pubkey(U256::from_be32(d3)); uint8_t pub3[65]; size_t l3=0; encode_pubkey(P3,true,pub3,l3);
        std::string ms = std::string("sortedmulti(2,")+hex_of(pub3,33)+","+hex_of(pub1,33)+","+hex_of(pub2,33)+")";
        std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(ms, ws)){ std::cerr<<"miniscript(sortedmulti) falhou\n"; return 1; }
        uint8_t wsh[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), wsh);
        std::vector<uint8_t> spk = {0x00,0x20}; spk.insert(spk.end(), wsh, wsh+32);
        bitcrypto::psbt2::PSBT2 P; P.tx_version=2;
        bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0x77, 32); I.vout=0; I.sequence=0xFFFFFFFF; I.has_witness_utxo=true; I.witness_utxo.value=90000; I.witness_utxo.scriptPubKey=spk; I.has_witness_script=true; I.witness_script=ws;
        P.ins.push_back(I);
        bitcrypto::psbt2::Out O; O.amount=80000; O.script=spk; P.outs.push_back(O);
        std::vector<std::vector<uint8_t>> ks; ks.push_back(std::vector<uint8_t>(d1,d1+32)); ks.push_back(std::vector<uint8_t>(d2,d2+32));
        bitcrypto::tx::Transaction txf;
        if (!bitcrypto::psbt2::sign_and_finalize_psbt2_multi(P, ks, bitcrypto::tx::SIGHASH_ALL, txf)){ std::cerr<<"P2WSH 2-of-3 falhou\n"; return 1; }
        if (txf.vin[0].witness.size()<4){ std::cerr<<"witness P2WSH 2-of-3 inválido\n"; return 1; }
    }
    // Nested P2SH-P2WSH
    {
        uint8_t d1[32]={0}; d1[31]=1; auto P1=Secp256k1::derive_pubkey(U256::from_be32(d1)); uint8_t pub1[65]; size_t l1=0; encode_pubkey(P1,true,pub1,l1);
        uint8_t d2[32]={0}; d2[31]=2; auto P2=Secp256k1::derive_pubkey(U256::from_be32(d2)); uint8_t pub2[65]; size_t l2=0; encode_pubkey(P2,true,pub2,l2);
        uint8_t d3[32]={0}; d3[31]=3; auto P3=Secp256k1::derive_pubkey(U256::from_be32(d3)); uint8_t pub3[65]; size_t l3=0; encode_pubkey(P3,true,pub3,l3);
        std::string ms = std::string("multi(2,")+hex_of(pub1,33)+","+hex_of(pub2,33)+","+hex_of(pub3,33)+")";
        std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(ms, ws)){ std::cerr<<"miniscript(multi) falhou\n"; return 1; }
        uint8_t wsh[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), wsh);
        std::vector<uint8_t> redeem = {0x00,0x20}; redeem.insert(redeem.end(), wsh, wsh+32);
        uint8_t sh160[20]; bitcrypto::hash::hash160(redeem.data(), redeem.size(), sh160);
        std::vector<uint8_t> spk = {0xA9,0x14}; spk.insert(spk.end(), sh160, sh160+20); spk.push_back(0x87);
        bitcrypto::psbt2::PSBT2 P; bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0x88, 32); I.vout=1; I.sequence=0xFFFFFFFF;
        I.has_witness_utxo=true; I.witness_utxo.value=150000; I.witness_utxo.scriptPubKey=spk;
        I.has_redeem_script=true; I.redeem_script=redeem;
        I.has_witness_script=true; I.witness_script=ws;
        P.ins.push_back(I);
        bitcrypto::psbt2::Out O; O.amount=149000; O.script=spk; P.outs.push_back(O);
        std::vector<std::vector<uint8_t>> ks; ks.push_back(std::vector<uint8_t>(d1,d1+32)); ks.push_back(std::vector<uint8_t>(d2,d2+32));
        bitcrypto::tx::Transaction txf;
        if (!bitcrypto::psbt2::sign_and_finalize_psbt2_multi(P, ks, bitcrypto::tx::SIGHASH_ALL, txf)){ std::cerr<<"P2SH-P2WSH 2-of-3 falhou\n"; return 1; }
        if (txf.vin[0].scriptSig.empty()) { std::cerr<<"scriptSig redeem ausente\n"; return 1; }
        if (txf.vin[0].witness.size()<4) { std::cerr<<"witness P2SH-P2WSH inválido\n"; return 1; }
    }
    // Nested P2SH-P2WPKH
    {
        uint8_t d[32]={0}; d[31]=7; auto Pk=Secp256k1::derive_pubkey(U256::from_be32(d)); uint8_t pub[65]; size_t pl=0; encode_pubkey(Pk,true,pub,pl);
        uint8_t pkh[20]; bitcrypto::hash::hash160(pub, pl, pkh);
        std::vector<uint8_t> redeem = {0x00,0x14}; redeem.insert(redeem.end(), pkh, pkh+20);
        uint8_t sh160[20]; bitcrypto::hash::hash160(redeem.data(), redeem.size(), sh160);
        std::vector<uint8_t> spk = {0xA9,0x14}; spk.insert(spk.end(), sh160, sh160+20); spk.push_back(0x87);
        bitcrypto::psbt2::PSBT2 P; bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0x99, 32); I.vout=0; I.sequence=0xFFFFFFFF;
        I.has_witness_utxo=true; I.witness_utxo.value=60000; I.witness_utxo.scriptPubKey=spk;
        I.has_redeem_script=true; I.redeem_script=redeem;
        P.ins.push_back(I);
        bitcrypto::psbt2::Out O; O.amount=55000; O.script=spk; P.outs.push_back(O);
        std::vector<std::vector<uint8_t>> ks; ks.push_back(std::vector<uint8_t>(d,d+32));
        bitcrypto::tx::Transaction txf;
        if (!bitcrypto::psbt2::sign_and_finalize_psbt2_multi(P, ks, bitcrypto::tx::SIGHASH_ALL, txf)){ std::cerr<<"P2SH-P2WPKH falhou\n"; return 1; }
        if (txf.vin[0].scriptSig.empty()) { std::cerr<<"scriptSig redeem ausente P2SH-P2WPKH\n"; return 1; }
        if (txf.vin[0].witness.size()<2) { std::cerr<<"witness P2SH-P2WPKH inválido\n"; return 1; }
    }
    std::cout<<"OK\n"; return 0;
}
