#include <iostream>
#include <vector>
#include <array>
#include <cstring>
#include <bitcrypto/schnorr/musig2.h>

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
    U256 d{{5,0,0,0}}; uint8_t priv32[32]; d.to_be32(priv32);
    uint8_t msg[32]{}; msg[0]=1;
    uint8_t sig_ref[64];
    if(!bitcrypto::sign::schnorr_sign_bip340(priv32, msg, sig_ref)){ std::cerr<<"schnorr_sign falhou\n"; return 1; }
    U256 s = U256::from_be32(sig_ref+32);
    U256 r = U256::from_be32(sig_ref);
    ECPointA R; if(!Secp256k1::lift_x_even_y(r, R)){ std::cerr<<"lift R falhou\n"; return 1; }
    ECPointA Pub = Secp256k1::derive_pubkey(d); uint8_t px[32]; bool neg=false; ECPointA PubEven = encoding::normalize_even_y(Pub, px, neg);
    std::vector<ECPointA> pubs1{PubEven}; std::vector<ECPointA> nonces1{R}; std::vector<U256> parts1{s};
    ECPointA Pcalc; uint8_t sig_out[64];
    if(!musig2_sign(pubs1, nonces1, parts1, Pcalc, sig_out)){ std::cerr<<"musig2_sign falhou\n"; return 1; }
    if (Pcalc.x.v[0]!=PubEven.x.v[0] || Pcalc.x.v[1]!=PubEven.x.v[1] ||
        Pcalc.x.v[2]!=PubEven.x.v[2] || Pcalc.x.v[3]!=PubEven.x.v[3] ||
        Pcalc.y.v[0]!=PubEven.y.v[0] || Pcalc.y.v[1]!=PubEven.y.v[1] ||
        Pcalc.y.v[2]!=PubEven.y.v[2] || Pcalc.y.v[3]!=PubEven.y.v[3]){
        std::cerr<<"agg key divergente\n"; return 1;
    }
    for(int i=0;i<64;i++){ if(sig_out[i]!=sig_ref[i]){ std::cerr<<"sig dif\n"; return 1; } }
    if(!musig2_verify(pubs1, nonces1, parts1, msg)){ std::cerr<<"musig2_verify falhou\n"; return 1; }
    parts1[0].v[0]^=1ULL; // negativo
    if(musig2_verify(pubs1, nonces1, parts1, msg)){ std::cerr<<"verificacao deveria falhar\n"; return 1; }
    return 0;
}
