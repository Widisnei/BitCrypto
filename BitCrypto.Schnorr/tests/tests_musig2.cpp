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

    // Agregação de nonces (soma simples de pontos)
    std::vector<ECPointA> Rs{P1, P2};
    ECPointA Ragg;
    if(!musig2_nonce_aggregate(Rs, Ragg)){ std::cerr<<"nonce agg falhou\n"; return 1; }
    std::vector<U256> ones{U256::one(), U256::one()};
    ECPointA Rexp; if(!msm_pippenger(Rs, ones, Rexp)){ std::cerr<<"msm falhou\n"; return 1; }
    U256 rx1=Ragg.x.to_u256_nm(), ry1=Ragg.y.to_u256_nm();
    U256 rx2=Rexp.x.to_u256_nm(), ry2=Rexp.y.to_u256_nm();
    for(int i=0;i<4;i++){ if(rx1.v[i]!=rx2.v[i]||ry1.v[i]!=ry2.v[i]){ std::cerr<<"nonce dif\n"; return 1; } }

    // Caso negativo: nonces vazios
    std::vector<ECPointA> rEmpty; ECPointA outR;
    if(musig2_nonce_aggregate(rEmpty, outR)){ std::cerr<<"nonce vazio deveria falhar\n"; return 1; }
    if(!outR.infinity){ std::cerr<<"nonce vazio nao infinito\n"; return 1; }

    // Agregação de assinaturas parciais
    U256 s1{{3,0,0,0}}, s2{{4,0,0,0}}, sAgg;
    std::vector<U256> parts{s1,s2};
    if(!musig2_partial_aggregate(parts, sAgg)){ std::cerr<<"sig agg falhou\n"; return 1; }
    Fn sum = Fn::add(Fn::from_u256_nm(s1), Fn::from_u256_nm(s2));
    U256 expected_s = sum.to_u256_nm();
    for(int i=0;i<4;i++){ if(expected_s.v[i]!=sAgg.v[i]){ std::cerr<<"sig dif\n"; return 1; } }

    // Caso negativo: entrada vazia
    std::vector<ECPointA> vazia; ECPointA out;
    if(musig2_key_aggregate(vazia, out)){ std::cerr<<"vazio deveria falhar\n"; return 1; }
    if(!out.infinity){ std::cerr<<"resultado nao infinito\n"; return 1; }

    std::vector<U256> sEmpty; U256 sOut;
    if(musig2_partial_aggregate(sEmpty, sOut)){ std::cerr<<"sig vazio deveria falhar\n"; return 1; }
    if(!sOut.is_zero()){ std::cerr<<"sig vazio nao zero\n"; return 1; }
    return 0;
}

