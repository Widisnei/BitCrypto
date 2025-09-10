#include <iostream>
#include <vector>
#include <array>
#include <cstring>
#include <bitcrypto/schnorr/musig2.h>
#include <bitcrypto/hash/tagged_hash.h>

using namespace bitcrypto;
using namespace bitcrypto::schnorr;

int main(){
    // Agregação básica de chaves
    U256 k1{{1,0,0,0}}; ECPointA P1 = Secp256k1::derive_pubkey(k1);
    U256 k2{{2,0,0,0}}; ECPointA P2 = Secp256k1::derive_pubkey(k2);
    std::vector<ECPointA> pubs{P1,P2}; ECPointA agg;
    if(!musig2_key_aggregate(pubs, agg)){ std::cerr<<"agg falhou\n"; return 1; }

    // Agregação de nonces
    std::vector<ECPointA> Rs{P1,P2}; ECPointA Ragg;
    if(!musig2_nonce_aggregate(Rs, Ragg)){ std::cerr<<"nonce agg falhou\n"; return 1; }

    // Agregação de assinaturas parciais
    U256 s1{{3,0,0,0}}, s2{{4,0,0,0}}, sAgg; std::vector<U256> parts{s1,s2};
    if(!musig2_partial_aggregate(parts, sAgg)){ std::cerr<<"sig agg falhou\n"; return 1; }

    // MuSig2 completo (1 participante)
    U256 d{{5,0,0,0}}; ECPointA Pub = Secp256k1::derive_pubkey(d);
    U256 k{{7,0,0,0}}; ECPointA R = Secp256k1::derive_pubkey(k);
    uint8_t rx[32]; R.x.to_u256_nm().to_be32(rx);
    uint8_t px[32]; Pub.x.to_u256_nm().to_be32(px);
    uint8_t msg[32]{}; msg[0]=1;
    uint8_t chal[96]; std::memcpy(chal, rx,32); std::memcpy(chal+32, px,32); std::memcpy(chal+64, msg,32);
    uint8_t e32[32]; hash::sha256_tagged("BIP0340/challenge", chal, sizeof(chal), e32);
    U256 e = U256::from_be32(e32); Secp256k1::scalar_mod_n(e);
    Fn s_fn = Fn::add(Fn::from_u256_nm(k), Fn::mul(Fn::from_u256_nm(e), Fn::from_u256_nm(d)));
    U256 s = s_fn.to_u256_nm();
    uint8_t sig_ref[64]; std::memcpy(sig_ref, rx,32); s.to_be32(sig_ref+32);
    std::vector<ECPointA> pubs1{Pub}; std::vector<ECPointA> nonces1{R}; std::vector<U256> parts1{s};
    ECPointA Pcalc; uint8_t sig_out[64];
    if(!musig2_sign(pubs1, nonces1, parts1, Pcalc, sig_out)){ std::cerr<<"musig2_sign falhou\n"; return 1; }
    for(int i=0;i<64;i++){ if(sig_out[i]!=sig_ref[i]){ std::cerr<<"sig dif\n"; return 1; } }
    if(!musig2_verify(pubs1, nonces1, parts1, msg)){ std::cerr<<"musig2_verify falhou\n"; return 1; }
    parts1[0].v[0]^=1ULL; // negativo
    if(musig2_verify(pubs1, nonces1, parts1, msg)){ std::cerr<<"verificacao deveria falhar\n"; return 1; }
    return 0;
}
