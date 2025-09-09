#include <iostream>
#include <vector>
#include <bitcrypto/msm_pippenger.h>

using namespace bitcrypto;

static bool eq(const ECPointA& A, const ECPointA& B){
    if (A.infinity != B.infinity) return false;
    for(int i=0;i<4;i++) if (A.x.v[i]!=B.x.v[i] || A.y.v[i]!=B.y.v[i]) return false;
    return true;
}

int main(){
    // Caso canônico: R = k·P único
    {
        ECPointA P = Secp256k1::G();
        U256 k{{5,0,0,0}};
        std::vector<ECPointA> pts{P};
        std::vector<U256> sc{k};
        ECPointA R;
        if (!msm_pippenger(pts, sc, R) || R.infinity){ std::cerr << "msm resultado incorreto\n"; return 1; }
    }
    // Caso negativo: tamanhos divergentes
    {
        ECPointA P = Secp256k1::G();
        std::vector<ECPointA> pts{P};
        std::vector<U256> sc; // vazio
        ECPointA R;
        if (msm_pippenger(pts, sc, R)){ std::cerr << "msm deveria falhar tamanhos\n"; return 1; }
    }
    std::cout << "OK\n";
    return 0;
}
