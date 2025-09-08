#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <bitcrypto/psbt2/psbt_v2.h>
#include <bitcrypto/psbt2/psbt_v2_sign.h>
#include <bitcrypto/encoding/base64.h>
#include <bitcrypto/encoding/wif.h>
#include <bitcrypto/psbt2/psbt_v2_verify.h>
#include <iomanip>

static int h2n(char c){ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return -1; }
static std::vector<uint8_t> hex_to_vec(const std::string& hs){ std::vector<uint8_t> v; if(hs.size()%2) return v; for(size_t i=0;i<hs.size();i+=2){ int a=h2n(hs[i]), b=h2n(hs[i+1]); if(a<0||b<0){ v.clear(); return v; } v.push_back((uint8_t)((a<<4)|b)); } return v; }
static std::string vec_to_hex(const std::vector<uint8_t>& v){ static const char* he="0123456789abcdef"; std::string s; s.resize(v.size()*2); for(size_t i=0;i<v.size();++i){ s[2*i]=he[v[i]>>4]; s[2*i+1]=he[v[i]&15]; } return s; }
static bool rdvi(const uint8_t* p, size_t n, size_t& o, uint64_t& v){
    if (o>=n) return false; uint8_t ch=p[o++];
    if (ch<0xFD){ v=ch; return true; }
    if (ch==0xFD){ if (o+2>n) return false; v=p[o]|(uint64_t)p[o+1]<<8; o+=2; return true; }
    if (ch==0xFE){ if (o+4>n) return false; v=0; for(int i=0;i<4;i++) v|=(uint64_t)p[o+i]<<(8*i); o+=4; return true; }
    if (ch==0xFF){ if (o+8>n) return false; v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[o+i]<<(8*i); o+=8; return true; }
    return false;
}

int main(int argc, char** argv){
    bool psbt2_sign_final=false; bool psbt2_decode=false; bool psbt2_verify=false; bool psbt2_pretty=false; std::string psbt_b64; std::vector<std::string> privs_hex; std::vector<std::string> privs_wif; std::string sighash_str="ALL"; bool anyonecanpay=false;
    bool infer_timelocks=false;
    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--psbt2-sign-final"){ psbt2_sign_final=true; }
        else if (a=="--psbt" && i+1<argc){ psbt_b64 = argv[++i]; }
        else if (a=="--priv" && i+1<argc){ privs_hex.push_back(argv[++i]); }
        else if (a=="--priv-wif" && i+1<argc){ privs_wif.push_back(argv[++i]); }
        else if (a=="--psbt2-decode"){ psbt2_decode=true; }
        else if (a=="--psbt2-verify"){ psbt2_verify=true; }
        else if (a=="--psbt2-pretty"){ psbt2_pretty=true; } else if (a=="--sighash" && i+1<argc){ sighash_str=argv[++i]; } else if (a=="--anyonecanpay"){ anyonecanpay=true; } else if (a=="--infer-timelocks"){ infer_timelocks=true; }
        else if (a=="--sighash" && i+1<argc){ sighash_str=argv[++i]; }
        else if (a=="--anyonecanpay"){ anyonecanpay=true; }
    }
    if (!(psbt2_sign_final||psbt2_decode||psbt2_verify||psbt2_pretty)){ std::cerr<<"Uso: (--psbt2-sign-final|--psbt2-decode|--psbt2-verify) --psbt <base64> [--priv <hex32> ... | --priv-wif <wif> ...]\n"; return 1; }
    std::vector<uint8_t> raw; if (!bitcrypto::encoding::base64_decode(psbt_b64, raw)){ std::cerr<<"base64 inválido\n"; return 1; }
    size_t off=0; if (raw.size()<5 || !(raw[0]==0x70&&raw[1]==0x73&&raw[2]==0x62&&raw[3]==0x74&&raw[4]==0xff)){ std::cerr<<"PSBT inválido\n"; return 1; } off=5;
    bitcrypto::psbt2::PSBT2 P2; P2.tx_version=2;
    while (true){
        if (off>=raw.size()){ std::cerr<<"PSBT truncado\n"; return 1; }
        if (raw[off]==0x00){ off++; break; }
        uint64_t klen=0; if(!rdvi(raw.data(),raw.size(),off,klen)) { std::cerr<<"parse falhou\n"; return 1; } const uint8_t* k=&raw[off]; off+=klen;
        uint64_t vlen=0; if(!rdvi(raw.data(),raw.size(),off,vlen)) { std::cerr<<"parse falhou\n"; return 1; } const uint8_t* v=&raw[off]; off+=vlen;
        if (klen==1 && k[0]==0x02 && vlen==4){ int32_t ver=0; for(int i=0;i<4;i++) ver |= (int32_t)v[i]<<(8*i); P2.tx_version = ver; }
        else if (klen==1 && k[0]==0x03 && vlen==4){ uint32_t lt=0; for(int i=0;i<4;i++) lt |= (uint32_t)v[i]<<(8*i); P2.tx_locktime = lt; }
    }
    while (off<raw.size()){
        if (raw[off]==0x00){ off++; break; }
        bitcrypto::psbt2::In I; std::memset(I.prev_txid, 0, 32);
        while (true){
            if (off>=raw.size()){ std::cerr<<"parse input falhou\n"; return 1; }
            if (raw[off]==0x00){ off++; break; }
            uint64_t klen=0; if(!rdvi(raw.data(),raw.size(),off,klen)){ std::cerr<<"parse falhou\n"; return 1; } const uint8_t* k=&raw[off]; off+=klen;
            uint64_t vlen=0; if(!rdvi(raw.data(),raw.size(),off,vlen)){ std::cerr<<"parse falhou\n"; return 1; } const uint8_t* v=&raw[off]; off+=vlen;
            if (klen==1 && k[0]==0x0e){ if (vlen!=32){ std::cerr<<"prev_txid inválido\n"; return 1; } std::memcpy(I.prev_txid, v, 32); }
            else if (klen==1 && k[0]==0x0f){ if (vlen!=4){ std::cerr<<"vout inválido\n"; return 1; } uint32_t vv=0; for(int i=0;i<4;i++) vv |= (uint32_t)v[i]<<(8*i); I.vout=vv; }
            else if (klen==1 && k[0]==0x10){ if (vlen!=4){ std::cerr<<"sequence inválido\n"; return 1; } uint32_t sq=0; for(int i=0;i<4;i++) sq |= (uint32_t)v[i]<<(8*i); I.sequence=sq; }
            else if (klen==1 && k[0]==0x01){ if (vlen<9){ std::cerr<<"witness_utxo inválido\n"; return 1; } uint64_t amount=0; for(int i=0;i<8;i++) amount |= (uint64_t)v[i]<<(8*i); size_t o=8; uint64_t sl=0; if(!rdvi(v,vlen,o,sl)){ std::cerr<<"witness_utxo inválido\n"; return 1; } if(o+sl>vlen){ std::cerr<<"witness_utxo inválido\n"; return 1; } I.has_witness_utxo=true; I.witness_utxo.value=amount; I.witness_utxo.scriptPubKey.assign(v+o, v+o+sl); }
            else if (klen==1 && k[0]==0x04){ I.has_redeem_script=true; I.redeem_script.assign(v, v+vlen); }
            else if (klen==1 && k[0]==0x05){ I.has_witness_script=true; I.witness_script.assign(v, v+vlen); }
        }
        P2.ins.push_back(I);
    }
    while (off<raw.size()){
        if (raw[off]==0x00){ off++; continue; }
        bitcrypto::psbt2::Out O;
        while (true){
            if (off>=raw.size()){ break; }
            if (raw[off]==0x00){ off++; break; }
            uint64_t klen=0; if(!rdvi(raw.data(),raw.size(),off,klen)){ std::cerr<<"parse falhou\n"; return 1; } const uint8_t* k=&raw[off]; off+=klen;
            uint64_t vlen=0; if(!rdvi(raw.data(),raw.size(),off,vlen)){ std::cerr<<"parse falhou\n"; return 1; } const uint8_t* v=&raw[off]; off+=vlen;
            if (klen==1 && k[0]==0x03){ if(vlen!=8){ std::cerr<<"amount inválido\n"; return 1; } uint64_t a=0; for(int i=0;i<8;i++) a|=(uint64_t)v[i]<<(8*i); O.amount=a; }
            else if (klen==1 && k[0]==0x04){ size_t o=0; uint64_t sl=0; if(!rdvi(v,vlen,o,sl)){ std::cerr<<"script inválido\n"; return 1; } if (o+sl>vlen){ std::cerr<<"script inválido\n"; return 1; } O.script.assign(v+o, v+o+sl); }
        }
        P2.outs.push_back(O);
    // decode / verify modes
    if (psbt2_decode || psbt2_verify || psbt2_pretty){
        if (psbt2_decode){
        if (psbt2_pretty){
            auto hex = [](const std::vector<uint8_t>& v){ std::ostringstream o; for (auto b: v) o<<std::hex<<std::setfill('0')<<std::setw(2)<<(int)b; return o.str(); };
            auto classify = [](const std::vector<uint8_t>& spk)->std::string{
                uint8_t tmp32[32], h160[20];
                if (bitcrypto::psbt2::is_p2wpkh(spk, h160)) return "p2wpkh(v0/20)";
                if (bitcrypto::psbt2::is_p2wsh(spk, tmp32)) return "p2wsh(v0/32)";
                if (bitcrypto::psbt2::is_p2tr(spk, tmp32)) return "p2tr(v1/32)";
                if (bitcrypto::psbt2::is_p2sh(spk, h160)) return "p2sh";
                if (bitcrypto::psbt2::is_p2pkh(spk, h160)) return "p2pkh";
                return "unknown";
            };
            std::cout<<"tx_version="<<P2.tx_version<<"\n";
            for (size_t i=0;i<P2.ins.size(); ++i){
                const auto& in = P2.ins[i];
                std::vector<uint8_t> spk = in.has_witness_utxo ? in.witness_utxo.scriptPubKey :
                    (in.has_non_witness_utxo && in.vout < in.non_witness_utxo.vout.size() ? in.non_witness_utxo.vout[in.vout].scriptPubKey : std::vector<uint8_t>());
                std::cout<<"in["<<i<<"] vout="<<in.vout<<" sequence="<<in.sequence
                         <<" has_wutxo="<<(in.has_witness_utxo?"1":"0")
                         <<" has_nwutxo="<<(in.has_non_witness_utxo?"1":"0")
                         <<" has_redeem="<<(in.has_redeem_script?"1":"0")
                         <<" has_wscript="<<(in.has_witness_script?"1":"0")
                         <<" type="<<(spk.empty()?"n/a":classify(spk))
                         <<" spk="<<(spk.empty()?"":hex(spk))<<"\n";
            }
            for (size_t i=0;i<P2.outs.size(); ++i){
                const auto& o = P2.outs[i];
                std::cout<<"out["<<i<<"] amount="<<o.amount<<" script_len="<<o.script.size()<<" spk="<<hex(o.script)<<"\n";
            }
        }

            std::cout<<"tx_version="<<P2.tx_version<<"\n";
            std::cout<<"inputs="<<P2.ins.size()<<" outputs="<<P2.outs.size()<<"\n";
            for (size_t i=0;i<P2.ins.size(); ++i){
                const auto& in = P2.ins[i];
                std::cout<<"in["<<i<<"] vout="<<in.vout<<" has_witness_utxo="<<(in.has_witness_utxo?"1":"0")
                         <<" has_nwutxo="<<(in.has_non_witness_utxo?"1":"0")
                         <<" has_redeem="<<(in.has_redeem_script?"1":"0")
                         <<" has_wscript="<<(in.has_witness_script?"1":"0")<<"\n";
            }
            for (size_t i=0;i<P2.outs.size(); ++i){
                std::cout<<"out["<<i<<"] amount="<<P2.outs[i].amount<<" script_size="<<P2.outs[i].script.size()<<"\n";
            }
        }
        if (psbt2_verify){
            std::string err; bool ok = bitcrypto::psbt2::verify_psbt2(P2, err);
            if (!ok){ std::cerr<<"PSBT2 verify: FAIL: "<<err<<"\n"; return 1; }
            std::cout<<"PSBT2 verify: OK\n";
        }
        return 0;
    }

    }
    
    // ---- Infer locktime/sequence from witness_script if requested ----
    if (infer_timelocks){
        uint32_t new_locktime = 0;
        for (size_t i=0;i<P2.ins.size(); ++i){
            if (P2.ins[i].has_witness_script){
                const auto& ws = P2.ins[i].witness_script;
                size_t offws = 0; uint64_t n = 0;
                if (read_push_number_le(ws, offws, n) && (offws+1)<ws.size()){
                    // OP_CHECKLOCKTIMEVERIFY (0xB1) OP_DROP (0x75)
                    if (ws[offws]==0xB1 && ws[offws+1]==0x75){
                        if (n > new_locktime) new_locktime = (uint32_t)n;
                        // BIP-65 exige sequence != 0xFFFFFFFF
                        if (P2.ins[i].sequence == 0xFFFFFFFF) P2.ins[i].sequence = 0xFFFFFFFE;
                    }
                    // OP_CHECKSEQUENCEVERIFY (0xB2) OP_DROP (0x75)
                    if (ws[offws]==0xB2 && ws[offws+1]==0x75){
                        // Define sequence relativa conforme n
                        if (P2.ins[i].sequence != (uint32_t)n) P2.ins[i].sequence = (uint32_t)n;
                    }
                }
            }
        }
        if (new_locktime > 0){
            P2.tx_version = (P2.tx_version==0) ? 2 : P2.tx_version; // manter pelo menos 2
            // Ajuste será aplicado via tx_out ao converter PSBT2->Transaction no signer
            // (sign_and_finalize_psbt2_multi usa P.tx_version, mas locktime é setado ao final)
        }
    }
    
    // Decode WIFs into priv32
for (auto& w : privs_wif){
    std::vector<uint8_t> d; bool compressed=false; bool is_testnet=false;
    if (!bitcrypto::encoding::wif_decode(w, d, compressed, is_testnet)){ std::cerr<<"WIF inválido: "<<w<<"\n"; return 1; }
    if (d.size()!=32){ std::cerr<<"WIF não resultou em 32 bytes\n"; return 1; }
    static const char hx[]="0123456789abcdef"; std::string h; h.resize(64);
    for (size_t i=0;i<32;i++){ h[2*i]=hx[d[i]>>4]; h[2*i+1]=hx[d[i]&0xF]; }
    privs_hex.push_back(h);
}
std::vector<std::vector<uint8_t>> ks; for (auto& s : privs_hex){ auto v=hex_to_vec(s); if (v.size()==32) ks.push_back(v); }
    if (ks.empty()){ std::cerr<<"Nenhuma chave privada válida\n"; return 1; }
    bitcrypto::tx::Transaction txf;
    if (!bitcrypto::psbt2::sign_and_finalize_psbt2_multi(P2, ks, bitcrypto::tx::SIGHASH_ALL, txf)){ std::cerr<<"Falha ao assinar PSBTv2\n"; return 1; }
    
    // Pós-fix: se inferimos CLTV, garanta que locktime do txf seja o máximo n encontrado.
    if (infer_timelocks){
        uint32_t maxlt = 0;
        for (size_t i=0;i<P2.ins.size(); ++i){
            if (P2.ins[i].has_witness_script){
                const auto& ws = P2.ins[i].witness_script;
                size_t offws = 0; uint64_t n = 0;
                if (read_push_number_le(ws, offws, n) && (offws+1)<ws.size()){
                    if (ws[offws]==0xB1 && ws[offws+1]==0x75){ if (n > maxlt) maxlt = (uint32_t)n; }
                }
            }
        }
        if (maxlt > 0){ txf.locktime = maxlt; }
    }
    
    std::cout<<vec_to_hex(txf.serialize())<<"\n";
    return 0;
}
