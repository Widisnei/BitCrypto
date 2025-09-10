#include <iostream>
#include <bitcrypto/endo_shamir.h>

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
    // shamir_trick: a*P + b*G
    {
        ECPointA G = Secp256k1::G();
        U256 two{{2,0,0,0}}; ECPointA Q = Secp256k1::to_affine(Secp256k1::scalar_mul(two, G));
        U256 a{{1,0,0,0}}, b{{3,0,0,0}}; ECPointA R;
        if(!shamir_trick(Q,a,b,R) || R.infinity){ std::cerr<<"shamir falhou\n"; return 1; }
    }
    // shamir_trick negativo: ponto infinito
    {
        ECPointA P{Fp::zero(),Fp::zero(),true}; U256 a{{1,0,0,0}}, b{{1,0,0,0}}; ECPointA R;
        if(shamir_trick(P,a,b,R)){ std::cerr<<"shamir deveria falhar\n"; return 1; }
    }
    std::cout<<"OK\n"; return 0;
}
