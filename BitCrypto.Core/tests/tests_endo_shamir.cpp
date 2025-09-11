#include <iostream>
#include <bitcrypto/endo_shamir.h>
#include <bitcrypto/rng.h>

using namespace bitcrypto;

int main(){
    // split_scalar_lambda: verifica r1 + lambda*r2 == k (mod n)
    {
        U256 k{{12345,0,0,0}}; U256 r1,r2; split_scalar_lambda(k,r1,r2);
        Fn lhs = Fn::add(Fn::from_u256_nm(r1), Fn::mul(Fn::from_u256_nm(r2), Fn::from_u256_nm(LAMBDA)));
        Fn rhs = Fn::from_u256_nm(k);
        if (lhs.v[0]!=rhs.v[0]||lhs.v[1]!=rhs.v[1]||lhs.v[2]!=rhs.v[2]||lhs.v[3]!=rhs.v[3]){ std::cerr<<"split incorreto\n"; return 1; }
    }
    // split_scalar_lambda com k=0
    {
        U256 k{{0,0,0,0}}; U256 r1,r2; split_scalar_lambda(k,r1,r2);
        if (!r1.is_zero() || !r2.is_zero()){ std::cerr<<"split zero\n"; return 1; }
    }
    // shamir_trick: compara a*P + b*G com a implementação direta
    {
        ECPointA G = Secp256k1::G();
        U256 two{{2,0,0,0}}; ECPointA P = Secp256k1::to_affine(Secp256k1::scalar_mul(two, G));
        U256 a{{1,0,0,0}}, b{{3,0,0,0}}; ECPointA R;
        if(!shamir_trick(P,a,b,R) || R.infinity){ std::cerr<<"shamir falhou\n"; return 1; }
        ECPointJ ap = Secp256k1::scalar_mul(a, P);
        ECPointJ bg = Secp256k1::scalar_mul(b, G);
        ECPointA naive = Secp256k1::to_affine(Secp256k1::add(ap, bg));
        if (R.x.v[0]!=naive.x.v[0]||R.x.v[1]!=naive.x.v[1]||R.x.v[2]!=naive.x.v[2]||R.x.v[3]!=naive.x.v[3]
         || R.y.v[0]!=naive.y.v[0]||R.y.v[1]!=naive.y.v[1]||R.y.v[2]!=naive.y.v[2]||R.y.v[3]!=naive.y.v[3]){
            std::cerr<<"shamir incorreto\n"; return 1;
        }
    }
    // shamir_trick com escalares grandes (n-1)
    {
        ECPointA G = Secp256k1::G();
        U256 k{{5,0,0,0}}; ECPointA P = Secp256k1::to_affine(Secp256k1::scalar_mul(k, G));
        U256 nm1{{Fn::N[0]-1ULL,Fn::N[1],Fn::N[2],Fn::N[3]}}; ECPointA R;
        if(!shamir_trick(P,nm1,nm1,R) || R.infinity || !Secp256k1::is_on_curve(R)){
            std::cerr<<"shamir n-1 falhou\n"; return 1;
        }
    }
    // shamir_trick com escalares aleatórios
    {
        ECPointA G = Secp256k1::G();
        U256 a,b,kp; rng_system((uint8_t*)&a,sizeof(a)); rng_system((uint8_t*)&b,sizeof(b)); rng_system((uint8_t*)&kp,sizeof(kp));
        a.v[3]|=0xFFFFFFFF00000000ULL; b.v[3]|=0xFFFFFFFF00000000ULL; kp.v[3]|=0xFFFFFFFF00000000ULL;
        Secp256k1::scalar_mod_n(a); Secp256k1::scalar_mod_n(b); Secp256k1::scalar_mod_n(kp);
        ECPointA P = Secp256k1::to_affine(Secp256k1::scalar_mul(kp, G));
        ECPointA R;
        if(!shamir_trick(P,a,b,R) || R.infinity){ std::cerr<<"shamir rand falhou\n"; return 1; }
        ECPointJ ap = Secp256k1::scalar_mul(a, P);
        ECPointJ bg = Secp256k1::scalar_mul(b, G);
        ECPointA naive = Secp256k1::to_affine(Secp256k1::add(ap, bg));
        if (R.x.v[0]!=naive.x.v[0]||R.x.v[1]!=naive.x.v[1]||R.x.v[2]!=naive.x.v[2]||R.x.v[3]!=naive.x.v[3]
         || R.y.v[0]!=naive.y.v[0]||R.y.v[1]!=naive.y.v[1]||R.y.v[2]!=naive.y.v[2]||R.y.v[3]!=naive.y.v[3]){
            std::cerr<<"shamir rand incorreto\n"; return 1;
        }
    }
    // shamir_trick negativo: ponto infinito
    {
        ECPointA P{Fp::zero(),Fp::zero(),true}; U256 a{{1,0,0,0}}, b{{1,0,0,0}}; ECPointA R;
        if(shamir_trick(P,a,b,R)){ std::cerr<<"shamir deveria falhar\n"; return 1; }
    }
    // shamir_trick negativo: ponto inválido
    {
        ECPointA P{Fp::zero(),Fp::zero(),false}; U256 a{{1,0,0,0}}, b{{1,0,0,0}}; ECPointA R;
        if(shamir_trick(P,a,b,R)){
            std::cerr<<"shamir aceitou ponto invalido\n"; return 1;
        }
    }
    std::cout<<"OK\n"; return 0;
}
