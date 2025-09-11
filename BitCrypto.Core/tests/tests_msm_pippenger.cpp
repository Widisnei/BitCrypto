#include <iostream>
#include <vector>
#include <random>
#include <bitcrypto/msm_pippenger.h>

using namespace bitcrypto;

int main(){
    // Caso canônico: duas entradas devem produzir 7*G
    {
        ECPointA G = Secp256k1::G();
        ECPointJ Gj = Secp256k1::to_jacobian(G);
        ECPointA Q = Secp256k1::to_affine(Secp256k1::add(Gj, Gj)); // 2*G
        std::vector<ECPointA> pts{G, Q};
        std::vector<U256> sc{U256{{1,0,0,0}}, U256{{3,0,0,0}}};
        ECPointA R;
        PippengerContext ctx;
        if (!msm_pippenger(pts, sc, R, &ctx) || R.infinity){ std::cerr << "msm incorreto\n"; return 1; }
        ECPointA R2;
        if (!msm_pippenger(pts, sc, R2, &ctx) || R2.infinity){ std::cerr << "msm incorreto ctx\n"; return 1; }
        if (R2.x.v[0]!=R.x.v[0] || R2.x.v[1]!=R.x.v[1] ||
            R2.x.v[2]!=R.x.v[2] || R2.x.v[3]!=R.x.v[3] ||
            R2.y.v[0]!=R.y.v[0] || R2.y.v[1]!=R.y.v[1] ||
            R2.y.v[2]!=R.y.v[2] || R2.y.v[3]!=R.y.v[3]){
            std::cerr << "resultado divergente ctx\n"; return 1;
        }
    }
    // Casos pseudo-aleatórios: compara MSM com somatório direto
    {
        std::mt19937_64 rng(123);
        for (int iter=0; iter<16; ++iter){
            // Par aleatório de ponto e escalar
            U256 k{{rng(), rng(), rng(), rng()}}; Secp256k1::scalar_mod_n(k);
            ECPointA P = Secp256k1::to_affine(Secp256k1::scalar_mul(k, Secp256k1::G()));
            U256 s{{rng(), rng(), rng(), rng()}}; Secp256k1::scalar_mod_n(s);
            std::vector<ECPointA> pts{P};
            std::vector<U256> sc{s};
            ECPointA Rmsm;
            if (!msm_pippenger(pts, sc, Rmsm, nullptr) || Rmsm.infinity){ std::cerr << "msm aleatório falhou\n"; return 1; }
            ECPointJ t = Secp256k1::scalar_mul(s, P);
            ECPointJ sum = Secp256k1::add(t, ECPointJ{Fp::zero(),Fp::zero(),Fp::zero()}); // usa add com infinito
            ECPointA Rdir = Secp256k1::to_affine(sum);
            if (Rmsm.x.v[0]!=Rdir.x.v[0] || Rmsm.x.v[1]!=Rdir.x.v[1] ||
                Rmsm.x.v[2]!=Rdir.x.v[2] || Rmsm.x.v[3]!=Rdir.x.v[3] ||
                Rmsm.y.v[0]!=Rdir.y.v[0] || Rmsm.y.v[1]!=Rdir.y.v[1] ||
                Rmsm.y.v[2]!=Rdir.y.v[2] || Rmsm.y.v[3]!=Rdir.y.v[3]){
                std::cerr << "msm divergente aleatório\n"; return 1;
            }
        }
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
    // Caso negativo: escalar zero (resultado deve ser infinito)
    {
        ECPointA G = Secp256k1::G();
        std::vector<ECPointA> pts{G};
        std::vector<U256> sc{U256{{0,0,0,0}}};
        ECPointA R;
        PippengerContext ctx;
        if (!msm_pippenger(pts, sc, R, &ctx) || !R.infinity){ std::cerr << "msm deveria ser infinito zero\n"; return 1; }
    }
    // Caso negativo: ponto inválido
    {
        ECPointA inval{Fp::zero(), Fp::zero(), false};
        std::vector<ECPointA> pts{inval};
        std::vector<U256> sc{U256{{1,0,0,0}}};
        ECPointA R;
        PippengerContext ctx;
        bool ok = msm_pippenger(pts, sc, R, &ctx);
        if (ok && Secp256k1::is_on_curve(R)){ std::cerr << "ponto inválido aceito\n"; return 1; }
    }
    std::cout << "OK\n";
    return 0;
}
