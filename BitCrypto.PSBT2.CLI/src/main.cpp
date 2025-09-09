#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <bitcrypto/ec_secp256k1.h>
#include <bitcrypto/base.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/hash/sha256.h>
#include <bitcrypto/hash/tagged_hash.h>
#include <bitcrypto/encoding/base64.h>
#include <bitcrypto/encoding/bech32.h>
#include <bitcrypto/encoding/address.h>
#include <bitcrypto/encoding/base58.h>
#include <bitcrypto/tx/tx.h>
#include <bitcrypto/tx/sign.h>
#include <bitcrypto/tx/miniscript.h>
#include <bitcrypto/psbt2/psbt_v2.h>
#include <bitcrypto/psbt2/psbt_v2_sign.h>

using namespace bitcrypto;

static std::string p2sh_address_from_hash160(const uint8_t h160[20], bool mainnet){
    std::vector<uint8_t> v; v.push_back(mainnet?0x05:0xC4); v.insert(v.end(), h160, h160+20);
    uint8_t c1[32]; bitcrypto::hash::sha256(v.data(), v.size(), c1);
    uint8_t c2[32]; bitcrypto::hash::sha256(c1, 32, c2);
    v.insert(v.end(), c2, c2+4);
    return bitcrypto::encoding::base58_encode(v.data(), v.size());
}


static std::string vec_to_hex(const std::vector<uint8_t>& v){
    static const char* he="0123456789abcdef"; std::string s; s.resize(v.size()*2);
    for (size_t i=0;i<v.size();++i){ s[2*i]=he[v[i]>>4]; s[2*i+1]=he[v[i]&15]; } return s;
}
static bool hex_to_vec(const std::string& hs, std::vector<uint8_t>& out){
    auto h2n=[&](char c)->int{ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return -1; };
    if (hs.size()%2) return false; out.clear();
    for(size_t i=0;i<hs.size();i+=2){ int a=h2n(hs[i]), b=h2n(hs[i+1]); if(a<0||b<0) return false; out.push_back((uint8_t)((a<<4)|b)); }
    return true;
}
static std::vector<uint8_t> push_data_script(const std::vector<uint8_t>& d){
    std::vector<uint8_t> s;
    if (d.size() < 0x4c){ s.push_back((uint8_t)d.size()); }
    else if (d.size() <= 0xFF){ s.push_back(0x4c); s.push_back((uint8_t)d.size()); }
    else { s.push_back(0x4d); s.push_back((uint8_t)(d.size()&0xFF)); s.push_back((uint8_t)((d.size()>>8)&0xFF)); }
    s.insert(s.end(), d.begin(), d.end());
    return s;
}

int main(int argc, char** argv){
    bool wscript_from_ms=false, p2wsh_from_ms=false, p2shwsh_from_ms=false, psbt2_sign_final=false;
    std::string ms_expr, hrp="tb";
    std::string psbt_b64;
    std::vector<std::string> in_addr_specs;   // "<txidLE>:<vout>:<amount>:<address>"
    std::vector<std::string> in_wscripts;     // "<index>:<wscriptHex>"
    std::vector<std::string> in_rscripts;     // "<index>:<redeemHex>"
    std::vector<std::string> privs_hex;

    for (int i=1;i<argc;i++){
        std::string a = argv[i];
        if (a=="--wscript-from-ms" && i+1<argc){ wscript_from_ms=true; ms_expr=argv[++i]; }
        else if (a=="--p2wsh-from-ms" && i+1<argc){ p2wsh_from_ms=true; ms_expr=argv[++i]; }
        else if (a=="--p2shwsh-from-ms" && i+1<argc){ p2shwsh_from_ms=true; ms_expr=argv[++i]; }
        else if (a=="--hrp" && i+1<argc){ hrp=argv[++i]; }
        else if (a=="--psbt2-create"){ /* no-op marker */ }
        else if (a=="--psbt2-sign-final"){ psbt2_sign_final=true; }
        else if (a=="--psbt" && i+1<argc){ psbt_b64=argv[++i]; }
        else if (a=="--tx-in-addr" && i+1<argc){ in_addr_specs.push_back(argv[++i]); }
        else if (a=="--tx-in-wscript" && i+1<argc){ in_wscripts.push_back(argv[++i]); }
        else if (a=="--tx-in-rscript" && i+1<argc){ in_rscripts.push_back(argv[++i]); }
        else if (a=="--priv" && i+1<argc){ privs_hex.push_back(argv[++i]); }
    }

    auto out_wscript_from_ms = [&]()->int{
        std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(ms_expr, ws)){ std::cerr<<"Miniscript inválido\n"; return 1; }
        std::cout<<vec_to_hex(ws)<<"\n"; return 0;
    };
    auto out_p2wsh_from_ms = [&]()->int{
        std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(ms_expr, ws)){ std::cerr<<"Miniscript inválido\n"; return 1; }
        uint8_t h[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), h);
        std::vector<uint8_t> prog(h,h+32), spk; bitcrypto::encoding::spk_witness(0, prog, spk);
        std::string addr; bitcrypto::encoding::segwit_addr_encode(addr, hrp, 0, prog);
        std::cout<<"wscript="<<vec_to_hex(ws)<<"\n";
        std::cout<<"scriptPubKey="<<vec_to_hex(spk)<<"\n";
        std::cout<<"address="<<addr<<"\n"; return 0;
    };
    auto out_p2shwsh_from_ms = [&]()->int{
        std::vector<uint8_t> ws; if (!bitcrypto::tx::miniscript_compile(ms_expr, ws)){ std::cerr<<"Miniscript inválido\n"; return 1; }
        uint8_t wsh[32]; bitcrypto::hash::sha256(ws.data(), ws.size(), wsh);
        std::vector<uint8_t> redeem = {0x00, 0x20}; redeem.insert(redeem.end(), wsh, wsh+32);
        uint8_t h160[20]; bitcrypto::hash::hash160(redeem.data(), redeem.size(), h160);
        std::vector<uint8_t> spk = {0xA9, 0x14}; spk.insert(spk.end(), h160, h160+20); spk.push_back(0x87);
        std::string addr = p2sh_address_from_hash160(h160, hrp=="bc");
        std::cout<<"wscript="<<vec_to_hex(ws)<<"\n";
        std::cout<<"redeemScript="<<vec_to_hex(redeem)<<"\n";
        std::cout<<"scriptPubKey="<<vec_to_hex(spk)<<"\n";
        std::cout<<"address="<<addr<<"\n"; return 0;
    };

    if (wscript_from_ms) return out_wscript_from_ms();
    if (p2wsh_from_ms) return out_p2wsh_from_ms();
    if (p2shwsh_from_ms) return out_p2shwsh_from_ms();

    // PSBTv2: sign & finalize (decoder included)
    if (psbt2_sign_final){
        if (privs_hex.empty()){ std::cerr<<"--priv <hex32> obrigatório (pode repetir)\n"; return 1; }
        if (psbt_b64.empty()){ std::cerr<<"--psbt <base64> obrigatório\n"; return 1; }
        // decoders
        auto rdvi = [&](const uint8_t* p, size_t n, size_t& o, uint64_t& v)->bool{
            if (o>=n) return false; uint8_t ch=p[o++];
            if (ch<0xFD){ v=ch; return true; }
            if (ch==0xFD){ if (o+2>n) return false; v=p[o]|(uint64_t)p[o+1]<<8; o+=2; return true; }
            if (ch==0xFE){ if (o+4>n) return false; v=0; for(int i=0;i<4;i++) v|=(uint64_t)p[o+i]<<(8*i); o+=4; return true; }
            if (ch==0xFF){ if (o+8>n) return false; v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[o+i]<<(8*i); o+=8; return true; }
            return false;
        };
        std::vector<uint8_t> raw; if (!bitcrypto::encoding::base64_decode(psbt_b64, raw)){ std::cerr<<"base64 inválido\n"; return 1; }
        size_t off=0; if (raw.size()<5 || !(raw[0]==0x70&&raw[1]==0x73&&raw[2]==0x62&&raw[3]==0x74&&raw[4]==0xff)){ std::cerr<<"PSBT inválido\n"; return 1; } off=5;
        bitcrypto::psbt2::PSBT2 P2; P2.tx_version=2;
        // globals (skip until 00)
        while (true){ if (off>=raw.size()){ std::cerr<<"PSBT truncado\n"; return 1; } if (raw[off]==0x00){ off++; break; } uint64_t klen=0; if(!rdvi(raw.data(),raw.size(),off,klen)) return 1; off+=klen; uint64_t vlen=0; if(!rdvi(raw.data(),raw.size(),off,vlen)) return 1; off+=vlen; }
        // each input map
        while (off<raw.size()){
            if (raw[off]==0x00){ off++; break; }
            bitcrypto::psbt2::In I;
            while (true){
                if (off>=raw.size()){ std::cerr<<"parse input falhou\n"; return 1; }
                if (raw[off]==0x00){ off++; break; }
                uint64_t klen=0; if(!rdvi(raw.data(),raw.size(),off,klen)) return 1; const uint8_t* k=&raw[off]; off+=klen;
                uint64_t vlen=0; if(!rdvi(raw.data(),raw.size(),off,vlen)) return 1; const uint8_t* v=&raw[off]; off+=vlen;
                if (klen==1 && k[0]==0x0e){ if (vlen!=32) return 1; std::memcpy(I.prev_txid, v, 32); }
                else if (klen==1 && k[0]==0x0f){ if (vlen!=4) return 1; uint32_t vv=0; for(int i=0;i<4;i++) vv |= (uint32_t)v[i]<<(8*i); I.vout=vv; }
                else if (klen==1 && k[0]==0x10){ if (vlen!=4) return 1; uint32_t sq=0; for(int i=0;i<4;i++) sq |= (uint32_t)v[i]<<(8*i); I.sequence=sq; }
                else if (klen==1 && k[0]==0x01){ if (vlen<9) return 1; uint64_t amount=0; for(int i=0;i<8;i++) amount |= (uint64_t)v[i]<<(8*i); size_t o=8; uint64_t sl=0; if(!rdvi(v,vlen,o,sl)) return 1; if(o+sl>vlen) return 1; I.has_witness_utxo=true; I.witness_utxo.value=amount; I.witness_utxo.scriptPubKey.assign(v+o, v+o+sl); }
                else if (klen==1 && k[0]==0x00){ I.has_non_witness_utxo=true; /* ignore raw prevtx here; not needed if witness_utxo present */ }
                else if (klen==1 && k[0]==0x05){ I.has_witness_script=true; I.witness_script.assign(v, v+vlen); }
                else if (klen==1 && k[0]==0x04){ I.has_redeem_script=true; I.redeem_script.assign(v, v+vlen); }
            }
            P2.ins.push_back(I);
        }
        // outputs
        while (off<raw.size()){
            if (raw[off]==0x00){ off++; if (off>=raw.size()) break; }
            bitcrypto::psbt2::Out O;
            while (true){
                if (off>=raw.size()){ break; }
                if (raw[off]==0x00){ off++; break; }
                uint64_t klen=0; if(!rdvi(raw.data(),raw.size(),off,klen)) return 1; const uint8_t* k=&raw[off]; off+=klen;
                uint64_t vlen=0; if(!rdvi(raw.data(),raw.size(),off,vlen)) return 1; const uint8_t* v=&raw[off]; off+=vlen;
                if (klen==1 && k[0]==0x03){ if(vlen!=8) return 1; uint64_t a=0; for(int i=0;i<8;i++) a|=(uint64_t)v[i]<<(8*i); O.amount=a; }
                else if (klen==1 && k[0]==0x04){ size_t o=0; uint64_t sl=0; if(!rdvi(v,vlen,o,sl)) return 1; if (o+sl>vlen) return 1; O.script.assign(v+o, v+o+sl); }
            }
            P2.outs.push_back(O);
        }
        std::vector<std::vector<uint8_t>> ks;
        for (auto& s : privs_hex){ std::vector<uint8_t> k; if (hex_to_vec(s,k) && k.size()==32) ks.push_back(k); }
        if (ks.empty()){ std::cerr<<"Nenhuma chave privada válida\n"; return 1; }
        bitcrypto::tx::Transaction txf;
        if (!bitcrypto::psbt2::sign_and_finalize_psbt2_multi(P2, ks, bitcrypto::tx::SIGHASH_ALL, txf)){ std::cerr<<"Falha ao assinar PSBTv2\n"; return 1; }
        std::vector<uint8_t> rawtx = txf.serialize();
        std::cout<<vec_to_hex(rawtx)<<"\n";
        return 0;
    }

    // If we reach here, either user asked for creation (separately) or misused tool
    std::cerr<<"Uso:\n"
             <<"  --wscript-from-ms \"<expr>\"\n"
             <<"  --p2wsh-from-ms \"<expr>\" [--hrp bc|tb]\n"
             <<"  --p2shwsh-from-ms \"<expr>\" [--hrp bc|tb]\n"
             <<"  --psbt2-sign-final --psbt <base64> --priv <hex32> [--priv <hex32> ...]\n";
    return 1;
}
