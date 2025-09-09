#include <iostream>
#include <vector>
#include <bitcrypto/msm_pippenger.h>

using namespace bitcrypto;

int main(){
    // Caso canônico: duas entradas devem produzir 7*G
    {
        ECPointA G = Secp256k1::G();
        U256 two{{2,0,0,0}};
        ECPointA Q = Secp256k1::to_affine(Secp256k1::scalar_mul(two, G));
        std::vector<ECPointA> pts{G, Q};
        std::vector<U256> sc{U256{{1,0,0,0}}, U256{{3,0,0,0}}};
        ECPointA R;
        PippengerContext ctx;
        if (!msm_pippenger(pts, sc, R, &ctx) || R.infinity){ std::cerr << "msm incorreto\n"; return 1; }
        ECPointA R2;
        if (!msm_pippenger(pts, sc, R2, &ctx) || R2.infinity){ std::cerr << "msm incorreto ctx\n"; return 1; }
    }
    // Caso negativo: tamanhos divergentes
    {
        ECPointA P = Secp256k1::G();
        std::vector<ECPointA> pts{P};
        std::vector<U256> sc; // vazio
        ECPointA R;
        PippengerContext ctx;
        if (msm_pippenger(pts, sc, R, &ctx) || !R.infinity){ std::cerr << "msm deveria falhar tamanhos\n"; return 1; }
    }
    // Caso negativo: entrada vazia
    {
        std::vector<ECPointA> pts;
        std::vector<U256> sc;
        ECPointA R;
        PippengerContext ctx;
        if (msm_pippenger(pts, sc, R, &ctx) || !R.infinity){ std::cerr << "msm deveria falhar vazio\n"; return 1; }
    }
    std::cout << "OK\n";
    return 0;
}
