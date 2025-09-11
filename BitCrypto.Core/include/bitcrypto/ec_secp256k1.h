#pragma once
#include "field_secp256k1.h"
namespace bitcrypto {
struct ECPointJ{ Fp X,Y,Z; };
struct ECPointA{ Fp x,y; bool infinity; };
struct Secp256k1{
    static BITCRYPTO_HD inline bool is_on_curve(const ECPointA& P){ if (P.infinity) return true; Fp y2 = Fp::sqr(P.y); Fp x3 = Fp::mul(Fp::mul(P.x,P.x), P.x); Fp rhs = Fp::add(x3, b()); return (y2.v[0]==rhs.v[0] && y2.v[1]==rhs.v[1] && y2.v[2]==rhs.v[2] && y2.v[3]==rhs.v[3]); }
    static BITCRYPTO_HD inline Fp b(){ U256 seven{{7,0,0,0}}; return Fp::from_u256_nm(seven); }
    static BITCRYPTO_HD inline bool lift_x_even_y(const U256& x, ECPointA& P){
        Fp X = Fp::from_u256_nm(x);
        Fp y2 = Fp::add(Fp::mul(Fp::mul(X,X),X), b());
        Fp Y = Fp::sqrt(y2);
        if (is_zero_fp(Y) && !is_zero_fp(y2)) return false;
        U256 yu = Y.to_u256_nm(); if (yu.v[0]&1ULL) Y = Fp::sub(Fp::zero(), Y);
        P = ECPointA{X, Y, false};
        return true;
    }
    static BITCRYPTO_HD inline ECPointA G(){
        U256 gx{{0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL}};
        U256 gy{{0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL}};
        return ECPointA{Fp::from_u256_nm(gx),Fp::from_u256_nm(gy),false};
    }
    static BITCRYPTO_HD inline bool is_infinity(const ECPointJ& P){ U256 z=P.Z.to_u256_nm(); return z.is_zero(); }
    static BITCRYPTO_HD inline bool is_zero_fp(const Fp& a){ return (a.v[0]|a.v[1]|a.v[2]|a.v[3])==0ULL; }
    static BITCRYPTO_HD inline ECPointJ to_jacobian(const ECPointA& P){ return ECPointJ{P.x,P.y,Fp::from_u256_nm(U256::one())}; }
    static BITCRYPTO_HD inline ECPointA to_affine(const ECPointJ& P){
        if (is_infinity(P)) return ECPointA{Fp::zero(),Fp::zero(),true};
        Fp zinv=Fp::inv(P.Z), z2=Fp::sqr(zinv), z3=Fp::mul(z2,zinv);
        return ECPointA{Fp::mul(P.X,z2), Fp::mul(P.Y,z3), false};
    }
    // Implementações ingênuas em coordenadas afins para garantir correção
    static BITCRYPTO_HD inline ECPointJ dbl(const ECPointJ& P){
        if (is_infinity(P)) return P;
        ECPointA A = to_affine(P);
        if (is_zero_fp(A.y)) return ECPointJ{Fp::zero(),Fp::zero(),Fp::zero()};
        Fp three = Fp::from_u256_nm(U256{{3,0,0,0}});
        Fp two   = Fp::from_u256_nm(U256{{2,0,0,0}});
        Fp slope = Fp::mul(three, Fp::sqr(A.x));
        Fp inv   = Fp::inv(Fp::mul(two, A.y));
        Fp m     = Fp::mul(slope, inv);
        Fp xr    = Fp::sub(Fp::sub(Fp::sqr(m), A.x), A.x);
        Fp yr    = Fp::sub(Fp::mul(m, Fp::sub(A.x, xr)), A.y);
        return to_jacobian(ECPointA{xr, yr, false});
    }
    static BITCRYPTO_HD inline ECPointJ add(const ECPointJ& P, const ECPointJ& Q){
        if (is_infinity(P)) return Q;
        if (is_infinity(Q)) return P;
        ECPointA A = to_affine(P);
        ECPointA B = to_affine(Q);
        if (A.x.v[0]==B.x.v[0] && A.x.v[1]==B.x.v[1] && A.x.v[2]==B.x.v[2] && A.x.v[3]==B.x.v[3]){
            if (A.y.v[0]==B.y.v[0] && A.y.v[1]==B.y.v[1] && A.y.v[2]==B.y.v[2] && A.y.v[3]==B.y.v[3]) return dbl(P);
            return ECPointJ{Fp::zero(),Fp::zero(),Fp::zero()};
        }
        Fp inv = Fp::inv(Fp::sub(B.x, A.x));
        Fp m   = Fp::mul(Fp::sub(B.y, A.y), inv);
        Fp xr  = Fp::sub(Fp::sub(Fp::sqr(m), A.x), B.x);
        Fp yr  = Fp::sub(Fp::mul(m, Fp::sub(A.x, xr)), A.y);
        return to_jacobian(ECPointA{xr, yr, false});
    }
    static BITCRYPTO_HD inline void cswap(ECPointJ& A, ECPointJ& B, uint64_t m){ for(int i=0;i<4;i++) cswap64(A.X.v[i],B.X.v[i],m); for(int i=0;i<4;i++) cswap64(A.Y.v[i],B.Y.v[i],m); for(int i=0;i<4;i++) cswap64(A.Z.v[i],B.Z.v[i],m); }
    static BITCRYPTO_HD inline ECPointJ scalar_mul(const U256& k, const ECPointA& P_aff){
        // Escada de Montgomery para evitar ramos dependentes do escalar
        ECPointJ R0{Fp::zero(),Fp::zero(),Fp::zero()};
        ECPointJ R1 = to_jacobian(P_aff);
        for (int i=255;i>=0;i--){
            uint64_t bit = (k.v[i/64]>>(i%64))&1ULL;
            uint64_t m = 0 - bit;         // máscara: 0xFFFF.. quando bit=1
            cswap(R0, R1, m);
            R1 = add(R0, R1);
            R0 = dbl(R0);
            cswap(R0, R1, m);
        }
        return R0;
    }
    // Caminho rápido público (não constant-time): wNAF com janela 5
    static inline ECPointJ scalar_mul_wnaf_public(const U256& k, const ECPointA& P_aff){
        const int W=5; const int WSIZE = 1<<(W-1); // 16
        // Precompute odd multiples [1P,3P,5P,...]
        ECPointA table[WSIZE];
        table[0]=P_aff;
        ECPointJ twoP = dbl(to_jacobian(P_aff));
        for (int i=1;i<WSIZE;i++){
            ECPointJ t = add(to_jacobian(table[i-1]), twoP);
            table[i] = to_affine(t);
        }
        // wNAF recoding
        int8_t naf[260]={0}; int len=0;
        U256 d = k;
        while (!(d.v[0]==0 && d.v[1]==0 && d.v[2]==0 && d.v[3]==0)){
            uint64_t odd = d.v[0] & 1ULL;
            int8_t zi=0;
            if (odd){
                uint64_t mod = d.v[0] & ((1u<<W)-1u);
                zi = (int8_t)(mod);
                if (zi > (1<<(W-1))){ zi = (int8_t)(zi - (1<<W)); }
                // d = d - zi
                uint64_t abszi = (zi<0)? (uint64_t)(-zi) : (uint64_t)zi;
                U256 sub{ {abszi,0,0,0} };
                if (zi>0){
                    // d -= zi
                    uint64_t br=0; d.v[0]=subb64(d.v[0], sub.v[0], br); d.v[1]=subb64(d.v[1], br, br);
                    d.v[2]=subb64(d.v[2], br, br); d.v[3]=subb64(d.v[3], br, br);
                } else {
                    // d += |zi|
                    uint64_t c=0; d.v[0]=addc64(d.v[0], sub.v[0], c); d.v[1]=addc64(d.v[1], c, c);
                    d.v[2]=addc64(d.v[2], c, c); d.v[3]=addc64(d.v[3], c, c);
                }
            }
            naf[len++]=zi;
            // d >>= 1 (propaga bits entre os 256 bits do escalar)
            d.v[3] >>= 1;
            d.v[3] |= (d.v[2] & 1ULL) << 63;
            d.v[2] >>= 1;
            d.v[2] |= (d.v[1] & 1ULL) << 63;
            d.v[1] >>= 1;
            d.v[1] |= (d.v[0] & 1ULL) << 63;
            d.v[0] >>= 1;
        }
        // Evaluate
        ECPointJ R{Fp::zero(),Fp::zero(),Fp::zero()};
        for (int i=len-1;i>=0;i--){
            R = dbl(R);
            int8_t zi = naf[i];
            if (zi){
                int idx = (abs(zi)-1)/2;
                ECPointA T = table[idx];
                if (zi<0){ Fp ny; ny = Fp::sub(Fp::zero(), T.y); T.y = ny; }
                R = add(R, to_jacobian(T));
            }
        }
        return R;
    }
    static BITCRYPTO_HD inline void scalar_mod_n(U256& k){
        const uint64_t N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
        uint64_t br=0; uint64_t t0=subb64(k.v[0],N[0],br), t1=subb64(k.v[1],N[1],br), t2=subb64(k.v[2],N[2],br), t3=subb64(k.v[3],N[3],br);
        uint64_t m=0-(uint64_t)(1-br); k.v[0]=(k.v[0]&~m)|(t0&m); k.v[1]=(k.v[1]&~m)|(t1&m); k.v[2]=(k.v[2]&~m)|(t2&m); k.v[3]=(k.v[3]&~m)|(t3&m);
    }
    static inline ECPointA derive_pubkey(const U256& priv){ U256 k=priv; scalar_mod_n(k); ECPointJ R=scalar_mul(k, G()); return to_affine(R); }
};
BITCRYPTO_HD inline void encode_pubkey(const ECPointA& A, bool compressed, uint8_t* out, size_t& out_len){
    if (A.infinity){ out_len=0; return; }
    U256 x=A.x.to_u256_nm(), y=A.y.to_u256_nm();
    if (compressed){ out[0]=(y.v[0]&1ULL)?0x03:0x02; x.to_be32(out+1); out_len=33; }
    else { out[0]=0x04; x.to_be32(out+1); y.to_be32(out+33); out_len=65; }
}
}