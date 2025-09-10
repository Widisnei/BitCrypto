#include <iostream>
#include <vector>
#include <array>
#include <cstring>
#include <bitcrypto/schnorr/musig2.h>
#include <bitcrypto/hash/sha256.h>

using namespace bitcrypto;
using namespace bitcrypto::schnorr;

int main(){
    // Pontos a partir de escalares conhecidos
    U256 k1{{1,0,0,0}}; ECPointA P1 = Secp256k1::derive_pubkey(k1);
    U256 k2{{2,0,0,0}}; ECPointA P2 = Secp256k1::derive_pubkey(k2);
    std::vector<ECPointA> pubs{P1, P2};
    ECPointA agg;
    if(!musig2_key_aggregate(pubs, agg)){ std::cerr << "agg falhou\n"; return 1; }

    // Recalcula manualmente para comparação
    std::array<uint8_t,32> x1, x2;
    P1.x.to_u256_nm().to_be32(x1.data());
    P2.x.to_u256_nm().to_be32(x2.data());
    std::vector<size_t> ord{0,1};
    if(std::memcmp(x2.data(), x1.data(),32)<0) std::swap(ord[0],ord[1]);
    std::vector<uint8_t> concat;
    concat.insert(concat.end(), ord[0]==0?x1.begin():x2.begin(), ord[0]==0?x1.end():x2.end());
    concat.insert(concat.end(), ord[1]==0?x1.begin():x2.begin(), ord[1]==0?x1.end():x2.end());
    uint8_t ell[32]; hash::sha256(concat.data(), concat.size(), ell);
    std::vector<U256> mus; std::vector<ECPointA> pts;
    for(size_t i=0;i<2;i++){
        size_t idx=ord[i];
        uint8_t buf[64]; std::memcpy(buf, ell,32);
        std::memcpy(buf+32, idx==0?x1.data():x2.data(),32);
        uint8_t mu32[32]; hash::sha256(buf,64,mu32);
        U256 mu = Fn::from_u256_nm(U256::from_be32(mu32)).to_u256_nm();
        mus.push_back(mu);
        pts.push_back(idx==0?P1:P2);
    }
    ECPointA expected; if(!msm_pippenger(pts, mus, expected)){ std::cerr<<"msm falhou\n"; return 1; }
    U256 ex = expected.x.to_u256_nm(), ax = agg.x.to_u256_nm();
    U256 ey = expected.y.to_u256_nm(), ay = agg.y.to_u256_nm();
    for(int i=0;i<4;i++){ if(ex.v[i]!=ax.v[i]||ey.v[i]!=ay.v[i]){ std::cerr<<"dif\n"; return 1; } }

    // Caso negativo: entrada vazia
    std::vector<ECPointA> vazia; ECPointA out;
    if(musig2_key_aggregate(vazia, out)){ std::cerr<<"vazio deveria falhar\n"; return 1; }
    if(!out.infinity){ std::cerr<<"resultado nao infinito\n"; return 1; }
    return 0;
}

