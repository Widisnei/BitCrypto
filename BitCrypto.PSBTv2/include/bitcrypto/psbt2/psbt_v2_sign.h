#pragma once
#include <cstdint>
#include <vector>
#include <cstring>
#include <bitcrypto/tx/sign.h>
#include <bitcrypto/tx/taproot.h>
#include <bitcrypto/hash/hash160.h>
#include <bitcrypto/hash/sha256.h>
#include "psbt_v2.h"

namespace bitcrypto { namespace psbt2 {

inline bitcrypto::tx::Transaction to_transaction(const PSBT2& P){
    bitcrypto::tx::Transaction tx; tx.version = P.tx_version; tx.locktime=P.tx_locktime;
    tx.vin.resize(P.ins.size());
    for (size_t i=0;i<P.ins.size(); ++i){
        std::memcpy(tx.vin[i].prevout.txid, P.ins[i].prev_txid, 32);
        tx.vin[i].prevout.vout = P.ins[i].vout;
        tx.vin[i].sequence = P.ins[i].sequence;
    }
    tx.vout.resize(P.outs.size());
    for (size_t i=0;i<P.outs.size(); ++i){
        tx.vout[i].value = P.outs[i].amount;
        tx.vout[i].scriptPubKey = P.outs[i].script;
    }
    return tx;
}

inline bool is_p2wpkh(const std::vector<uint8_t>& spk, uint8_t out_h160[20]){
    if (spk.size()==22 && spk[0]==0x00 && spk[1]==0x14){ std::memcpy(out_h160, &spk[2], 20); return true; }
    return false;
}
inline bool is_p2tr(const std::vector<uint8_t>& spk, uint8_t out_x[32]){
    if (spk.size()==34 && spk[0]==0x51 && spk[1]==0x20){ std::memcpy(out_x, &spk[2], 32); return true; }
    return false;
}
inline bool is_p2sh(const std::vector<uint8_t>& spk, uint8_t out_h160[20]){
    if (spk.size()==23 && spk[0]==0xA9 && spk[1]==0x14 && spk[22]==0x87){ std::memcpy(out_h160, &spk[2], 20); return true; }
    return false;
}
inline bool is_p2pkh(const std::vector<uint8_t>& spk, uint8_t out_h160[20]){
    if (spk.size()==25 && spk[0]==0x76 && spk[1]==0xA9 && spk[2]==0x14 && spk[23]==0x88 && spk[24]==0xAC){ std::memcpy(out_h160, &spk[3], 20); return true; }
    return false;
}
inline bool is_p2wsh(const std::vector<uint8_t>& spk, uint8_t out_sha256[32]){
    if (spk.size()==34 && spk[0]==0x00 && spk[1]==0x20){ std::memcpy(out_sha256, &spk[2], 32); return true; }
    return false;
}


// Single-key witness script: either <pub> OP_CHECKSIG  OR  DUP HASH160 <20> EQUALVERIFY CHECKSIG
inline bool parse_wscript_single(const std::vector<uint8_t>& ws, std::vector<uint8_t>& pubkey33, uint8_t h160[20], bool& is_p2pk_script, bool& is_p2pkh_script){
    is_p2pk_script=false; is_p2pkh_script=false; pubkey33.clear();
    if (ws.size()==35 && ws[0]==0x21 && ws[34]==0xAC){ pubkey33.assign(ws.begin()+1, ws.begin()+34); is_p2pk_script=true; return true; }
    if (ws.size()==25 && ws[0]==0x76 && ws[1]==0xA9 && ws[2]==0x14 && ws[23]==0x88 && ws[24]==0xAC){
        std::memcpy(h160, &ws[3], 20); is_p2pkh_script=true; return true;
    }
    return false;
}

// --- Multisig parser: OP_m <33 pub>... OP_n OP_CHECKMULTISIG
inline bool parse_wscript_multisig(const std::vector<uint8_t>& ws, int& m, int& n, std::vector<std::vector<uint8_t>>& pubs){
    m=0; n=0; pubs.clear();
    size_t i=0; auto getop=[&](uint8_t& op)->bool{ if(i>=ws.size()) return false; op=ws[i++]; return true; };
    uint8_t op;
    if(!getop(op)) return false;
    if (op==0x00) m=0; else if (op>=0x51 && op<=0x60) m = op - 0x50; else return false;
    while (i<ws.size()){
        uint8_t b = ws[i];
        if (b>=0x51 && b<=0x60){
            n = b - 0x50;
            i++;
            if (i>=ws.size() || ws[i++]!=0xAE) return false; // OP_CHECKMULTISIG
            return (m>=1 && n>=m && !pubs.empty());
        }
        if (b!=0x21 || i+1+33>ws.size()) return false;
        i++; std::vector<uint8_t> pk(ws.begin()+i, ws.begin()+i+33); pubs.push_back(pk); i+=33;
    }
    return false;
}

// Single-key convenience: signs all inputs using one key (kept for compatibility)
inline bool sign_and_finalize_psbt2(const PSBT2& P, const uint8_t priv32[32], uint32_t sighash_type, bitcrypto::tx::Transaction& tx_out);

// Multi-key: sign each input with matching key (supports P2WPKH, P2TR key-path, P2WSH single-sig and multisig m-of-n, P2PKH legacy)
inline bool sign_and_finalize_psbt2_multi(const PSBT2& P, const std::vector<std::vector<uint8_t>>& privkeys, uint32_t sighash_type, bitcrypto::tx::Transaction& tx_out){
    using namespace bitcrypto;
    tx_out = to_transaction(P);
    struct KeyInfo { std::vector<uint8_t> priv; std::vector<uint8_t> pub33; uint8_t h160[20]; uint8_t xonly_q[32]; bool has_xonly=false; };
    std::vector<KeyInfo> infos;
    for (auto& k : privkeys){
        if (k.size()!=32) continue;
        U256 d = U256::from_be32(k.data()); Secp256k1::scalar_mod_n(d); if (d.is_zero()) continue;
        auto Ppub = Secp256k1::derive_pubkey(d); uint8_t pub[65]; size_t plen=0; encode_pubkey(Ppub, true, pub, plen);
        KeyInfo ki; ki.priv = k; ki.pub33.assign(pub, pub+plen); bitcrypto::hash::hash160(pub, plen, ki.h160);
        uint8_t px[32]; bool odd=false; bitcrypto::tx::xonly_from_point(Ppub, px, odd);
        std::vector<uint8_t> msg; msg.insert(msg.end(), px, px+32); uint8_t th[32]; bitcrypto::tx::tagged_hash("TapTweak", msg, th);
        auto t = U256::from_be32(th); Secp256k1::scalar_mod_n(t);
        auto Q = Secp256k1::add(Secp256k1::to_jacobian(Ppub), Secp256k1::scalar_mul(t, Secp256k1::G()));
        auto Qa = Secp256k1::to_affine(Q); bitcrypto::tx::xonly_from_point(Qa, ki.xonly_q, odd); ki.has_xonly=true;
        infos.push_back(ki);
    }
    std::vector<uint64_t> amts(P.ins.size(), 0);
    std::vector<std::vector<uint8_t>> spks(P.ins.size());
    for (size_t i=0;i<P.ins.size(); ++i){
        if (P.ins[i].has_witness_utxo){ amts[i]=P.ins[i].witness_utxo.value; spks[i]=P.ins[i].witness_utxo.scriptPubKey; }
        else if (P.ins[i].has_non_witness_utxo){
            // attempt to recover scriptPubKey from non_witness_utxo
            if (P.ins[i].non_witness_utxo.vout.size()>P.ins[i].vout){
                spks[i] = P.ins[i].non_witness_utxo.vout[P.ins[i].vout].scriptPubKey;
                amts[i] = P.ins[i].non_witness_utxo.vout[P.ins[i].vout].value;
            }
        }
    }
    for (size_t i=0;i<P.ins.size(); ++i){
        const auto& in = P.ins[i];
        bool signed_ok=false;
        if (!spks[i].empty()){
            auto& spk = spks[i];
            uint8_t buf32[32], h160[20];
            if (is_p2wpkh(spk, h160)){
                for (auto& ki: infos){ if (std::memcmp(ki.h160, h160, 20)==0){
                    if (!bitcrypto::tx::sign_input_p2wpkh(tx_out, i, ki.priv.data(), ki.h160, amts[i], sighash_type)) return false;
                    signed_ok=true; break;
                }}
                if (!signed_ok) return false; continue;
            }
            if (is_p2tr(spk, buf32)){
                for (auto& ki: infos){ if (std::memcmp(ki.xonly_q, buf32, 32)==0){
                    if (!bitcrypto::tx::sign_input_p2tr_keypath(tx_out, i, ki.priv.data(), amts, spks, sighash_type)) return false;
                    signed_ok=true; break;
                }}
                if (!signed_ok) return false; continue;
            }
            if (is_p2wsh(spk, buf32)){
                if (!in.has_witness_script) return false;
                uint8_t h[32]; bitcrypto::hash::sha256(in.witness_script.data(), in.witness_script.size(), h);
                if (std::memcmp(h, buf32, 32)!=0) return false;
                // Try multisig
                int m=0,n=0; std::vector<std::vector<uint8_t>> pubs;
                if (parse_wscript_multisig(in.witness_script, m, n, pubs)){
                    std::vector<std::vector<uint8_t>> sigs; sigs.reserve(pubs.size());
                    for (size_t pi=0; pi<pubs.size(); ++pi){
                        for (auto& ki : infos){ if (ki.pub33==pubs[pi]){
                            std::vector<uint8_t> sc = in.witness_script; uint8_t sh[32];
                            bitcrypto::tx::sighash_segwit_v0_all(tx_out, i, sc, amts[i], sh);
                            bitcrypto::sign::ECDSA_Signature sig{}; if (!bitcrypto::sign::ecdsa_sign_rfc6979(ki.priv.data(), sh, sig)) return false;
                            std::vector<uint8_t> der; bitcrypto::tx::serialize_der_sig_with_hashbyte(sig, sighash_type, der);
                            sigs.push_back(der); break;
                        }}
                    }
                    if ((int)sigs.size() < m) return false;
                    tx_out.vin[i].witness.clear(); tx_out.vin[i].witness.push_back(std::vector<uint8_t>()); // dummy
                    for (int k=0;k<m;++k) tx_out.vin[i].witness.push_back(sigs[k]);
                    tx_out.vin[i].witness.push_back(in.witness_script);
                    signed_ok=true; tx_out.has_witness=true; tx_out.set_segwit_if_any_witness(); continue;
                }
                // Single-sig forms (P2PK/P2PKH in wscript)
                std::vector<uint8_t> pk33; uint8_t h160ws[20]; bool is_p2pk=false, is_p2pkh=false;
                // reuse simple checks:
                if (in.witness_script.size()==35 && in.witness_script[0]==0x21 && in.witness_script[34]==0xAC){ is_p2pk=true; pk33.assign(in.witness_script.begin()+1, in.witness_script.begin()+34); }
                else if (in.witness_script.size()==25 && in.witness_script[0]==0x76 && in.witness_script[1]==0xA9 && in.witness_script[2]==0x14 && in.witness_script[23]==0x88 && in.witness_script[24]==0xAC){ is_p2pkh=true; std::memcpy(h160ws, &in.witness_script[3], 20); }
                if (!(is_p2pk||is_p2pkh)) return false;
                for (auto& ki : infos){
                    bool match=false; if (is_p2pk) match=(ki.pub33==pk33); else match=(std::memcmp(h160ws, ki.h160, 20)==0);
                    if (!match) continue;
                    std::vector<uint8_t> sc = in.witness_script; uint8_t sh[32]; bitcrypto::tx::sighash_segwit_v0_all(tx_out, i, sc, amts[i], sh);
                    bitcrypto::sign::ECDSA_Signature sig{}; if (!bitcrypto::sign::ecdsa_sign_rfc6979(ki.priv.data(), sh, sig)) return false;
                    std::vector<uint8_t> der; bitcrypto::tx::serialize_der_sig_with_hashbyte(sig, sighash_type, der);
                    tx_out.vin[i].witness.clear(); tx_out.vin[i].witness.push_back(der); if (is_p2pkh) tx_out.vin[i].witness.push_back(ki.pub33); tx_out.vin[i].witness.push_back(in.witness_script);
                    signed_ok=true; tx_out.has_witness=true; tx_out.set_segwit_if_any_witness(); break;
                }
                if (!signed_ok) return false; continue;
            }
            // P2SH-P2WPKH (redeem_script = v0/20B program)
        if (is_p2sh(spk, h160)){
            if (!in.has_redeem_script) return false;
            const auto& rs = in.redeem_script;
            if (rs.size()==22 && rs[0]==0x00 && rs[1]==0x14){
                uint8_t hh[20]; std::memcpy(hh, &rs[2], 20);
                bool ok=false;
                for (auto& ki: infos){ if (std::memcmp(ki.h160, hh, 20)==0){
                    if (!bitcrypto::tx::sign_input_p2wpkh(tx_out, i, ki.priv.data(), ki.h160, amts[i], sighash_type)) return false;
                    tx_out.vin[i].scriptSig.clear(); tx_out.vin[i].scriptSig.push_back((uint8_t)rs.size()); tx_out.vin[i].scriptSig.insert(tx_out.vin[i].scriptSig.end(), rs.begin(), rs.end());
                    ok=true; break;
                }}
                if (!ok) return false;
                tx_out.has_witness=true; tx_out.set_segwit_if_any_witness();
                continue;
            }
            // else: maybe P2SH-P2WSH
            if (rs.size()==34 && rs[0]==0x00 && rs[1]==0x20){
                if (!in.has_witness_script) return false;
                uint8_t prog[32]; std::memcpy(prog, &rs[2], 32);
                uint8_t hcalc[32]; bitcrypto::hash::sha256(in.witness_script.data(), in.witness_script.size(), hcalc);
                if (std::memcmp(prog, hcalc, 32)!=0) return false;
                // Try single-sig first
                std::vector<uint8_t> pk33; uint8_t h160ws[20]; bool is_p2pk=false, is_p2pkh=false;
                if (parse_wscript_single(in.witness_script, pk33, h160ws, is_p2pk, is_p2pkh)){
                    bool found=false;
                    for (auto& ki: infos){
                        bool match=false; if (is_p2pk){ match=(pk33==ki.pub33);} else if (is_p2pkh){ match=(std::memcmp(h160ws, ki.h160, 20)==0); }
                        if (!match) continue;
                        uint8_t shh[32]; std::vector<uint8_t> sc=in.witness_script; bitcrypto::tx::sighash_segwit_v0_all(tx_out, i, sc, amts[i], shh);
                        bitcrypto::sign::ECDSA_Signature sig{}; if (!bitcrypto::sign::ecdsa_sign_rfc6979(ki.priv.data(), shh, sig)) return false;
                        std::vector<uint8_t> sigder; bitcrypto::tx::serialize_der_sig_with_hashbyte(sig, sighash_type, sigder);
                        tx_out.vin[i].witness.clear(); tx_out.vin[i].witness.push_back(sigder); if (is_p2pkh) tx_out.vin[i].witness.push_back(ki.pub33);
                        tx_out.vin[i].witness.push_back(in.witness_script);
                        // scriptSig = push redeem
                        tx_out.vin[i].scriptSig.clear(); tx_out.vin[i].scriptSig.push_back((uint8_t)rs.size()); tx_out.vin[i].scriptSig.insert(tx_out.vin[i].scriptSig.end(), rs.begin(), rs.end());
                        found=true; break;
                    }
                    if (!found) return false; tx_out.has_witness=true; tx_out.set_segwit_if_any_witness(); continue;
                }
                // Multisig P2SH-P2WSH
                int mreq=0,n=0; std::vector<std::vector<uint8_t>> pubs;
                if (!parse_wscript_multisig(in.witness_script, mreq, n, pubs)) return false;
                std::vector<std::vector<uint8_t>> sigs;
                for (auto& pub : pubs){
                    for (auto& ki : infos){
                        if (pub==ki.pub33){
                            uint8_t sh2[32]; std::vector<uint8_t> sc=in.witness_script; bitcrypto::tx::sighash_segwit_v0_all(tx_out, i, sc, amts[i], sh2);
                            bitcrypto::sign::ECDSA_Signature sig{}; if (!bitcrypto::sign::ecdsa_sign_rfc6979(ki.priv.data(), sh2, sig)) return false;
                            std::vector<uint8_t> sigder; bitcrypto::tx::serialize_der_sig_with_hashbyte(sig, sighash_type, sigder);
                            sigs.push_back(sigder); break;
                        }
                    }
                    if ((int)sigs.size()==mreq) break;
                }
                if ((int)sigs.size() < mreq) return false;
                tx_out.vin[i].witness.clear(); tx_out.vin[i].witness.push_back(std::vector<uint8_t>());
                for (int k=0;k<mreq;k++) tx_out.vin[i].witness.push_back(sigs[k]);
                tx_out.vin[i].witness.push_back(in.witness_script);
                tx_out.vin[i].scriptSig.clear(); tx_out.vin[i].scriptSig.push_back((uint8_t)rs.size()); tx_out.vin[i].scriptSig.insert(tx_out.vin[i].scriptSig.end(), rs.begin(), rs.end());
                tx_out.has_witness=true; tx_out.set_segwit_if_any_witness(); continue;
            }
        }
        // Legacy P2PKH via non_witness_utxo
            if (is_p2pkh(spk, h160)){
                for (auto& ki: infos){ if (std::memcmp(ki.h160, h160, 20)==0){
                    if (!bitcrypto::tx::sign_input_p2pkh(tx_out, i, ki.priv.data(), ki.h160, sighash_type)) return false;
                    signed_ok=true; break;
                }}
                if (!signed_ok) return false; continue;
            }
            return false;
        } else {
            // If no spk recovered, can't sign
            return false;
        }
    }
    tx_out.set_segwit_if_any_witness();
    return true;
}

inline bool sign_and_finalize_psbt2(const PSBT2& P, const uint8_t priv32[32], uint32_t sighash_type, bitcrypto::tx::Transaction& tx_out){
    std::vector<std::vector<uint8_t>> ks; ks.emplace_back(priv32, priv32+32);
    return sign_and_finalize_psbt2_multi(P, ks, sighash_type, tx_out);
}

}} // ns
