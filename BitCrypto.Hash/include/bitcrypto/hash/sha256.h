#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>

namespace bitcrypto { namespace hash { namespace sha256 {

struct SHA256 {
    uint32_t h[8];
    uint8_t  buf[64];
    size_t   buf_len;
    unsigned long long total_bits;

    static inline uint32_t rotr(uint32_t x, int n){ return (x>>n) | (x<<(32-n)); }

    void init(){
        h[0]=0x6a09e667u; h[1]=0xbb67ae85u; h[2]=0x3c6ef372u; h[3]=0xa54ff53au;
        h[4]=0x510e527fu; h[5]=0x9b05688cu; h[6]=0x1f83d9abu; h[7]=0x5be0cd19u;
        buf_len=0; total_bits=0;
    }

    static inline void transform(uint32_t h[8], const uint8_t block[64]){
        static const uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };
        #define Ch(x,y,z) (((x)&(y)) ^ (~(x)&(z)))
        #define Maj(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
        #define S0(x) (rotr((x),2) ^ rotr((x),13) ^ rotr((x),22))
        #define S1(x) (rotr((x),6) ^ rotr((x),11) ^ rotr((x),25))
        #define s0(x) (rotr((x),7) ^ rotr((x),18) ^ ((x)>>3))
        #define s1(x) (rotr((x),17) ^ rotr((x),19) ^ ((x)>>10))
        uint32_t w[64];
        for (int i=0;i<16;i++){
            w[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
                   ((uint32_t)block[4*i+2] << 8) | (uint32_t)block[4*i+3];
        }
        for (int i=16;i<64;i++){ w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]); }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        #define SHA256_RND(i) do{ \
            uint32_t T1 = hh + S1(e) + Ch(e,f,g) + K[i] + w[i]; \
            uint32_t T2 = S0(a) + Maj(a,b,c); \
            hh = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2; \
        }while(0)
        for (int i=0;i<64; i+=8){ SHA256_RND(i+0); SHA256_RND(i+1); SHA256_RND(i+2); SHA256_RND(i+3); SHA256_RND(i+4); SHA256_RND(i+5); SHA256_RND(i+6); SHA256_RND(i+7); }
        #undef SHA256_RND
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
        #undef Ch
        #undef Maj
        #undef S0
        #undef S1
        #undef s0
        #undef s1
    };
        uint32_t w[64];
        for (int i=0;i<16;i++){
            w[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
                   ((uint32_t)block[4*i+2] << 8) | (uint32_t)block[4*i+3];
        }
        for (int i=16;i<64;i++){
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i=0;i<64;i++){
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const uint8_t* data, size_t len){
        total_bits += (unsigned long long)len * 8ull;
        size_t off=0;
        if (buf_len){
            size_t take = (len < (64 - buf_len)) ? len : (64 - buf_len);
            for (size_t i=0;i<take;i++) buf[buf_len+i]=data[i];
            buf_len += take; off += take;
            if (buf_len==64){ transform(h, buf); buf_len=0; }
        }
        while (off + 64 <= len){
            transform(h, data+off); off += 64;
        }
        size_t rem = len - off;
        for (size_t i=0;i<rem;i++) buf[i]=data[off+i];
        buf_len = rem;
    }

    void finalize(uint8_t out[32]){
        // pad
        buf[buf_len++] = 0x80;
        if (buf_len > 56){
            while (buf_len<64) buf[buf_len++]=0;
            transform(h, buf); buf_len=0;
        }
        while (buf_len<56) buf[buf_len++]=0;
        // length big-endian 64-bit
        unsigned long long tb = total_bits;
        for (int i=7;i>=0;--i){ buf[56+(7-i)] = (uint8_t)((tb>>(i*8)) & 0xFF); }
        transform(h, buf);
        for (int i=0;i<8;i++){
            out[4*i+0] = (uint8_t)((h[i]>>24)&0xFF);
            out[4*i+1] = (uint8_t)((h[i]>>16)&0xFF);
            out[4*i+2] = (uint8_t)((h[i]>> 8)&0xFF);
            out[4*i+3] = (uint8_t)((h[i]     )&0xFF);
        }
    }

    static inline std::array<uint8_t,32> hash(const std::vector<uint8_t>& in){
        SHA256 S; S.init(); if (!in.empty()) S.update(in.data(), in.size()); std::array<uint8_t,32> out{}; S.finalize(out.data()); return out;
    }

    static inline std::array<uint8_t,32> hash_bytes(const uint8_t* d, size_t n){
        SHA256 S; S.init(); if (n) S.update(d, n); std::array<uint8_t,32> out{}; S.finalize(out.data()); return out;
    }

    static inline std::array<uint8_t,32> tagged_hash(const std::string& tag, const std::vector<uint8_t>& data){
        auto tagh = hash_bytes(reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
        std::vector<uint8_t> buf; buf.reserve(64 + data.size());
        buf.insert(buf.end(), tagh.begin(), tagh.end());
        buf.insert(buf.end(), tagh.begin(), tagh.end());
        buf.insert(buf.end(), data.begin(), data.end());
        return hash(buf);
    }
};

}}} // ns
