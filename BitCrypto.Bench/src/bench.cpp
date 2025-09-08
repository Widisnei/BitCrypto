#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <cstring>
#include "../../BitCrypto.Core/include/bitcrypto/ec_secp256k1.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/hash160.h"
#include "../../BitCrypto.Hash/include/bitcrypto/hash/tagged_hash.h"
#include "../../BitCrypto.Encoding/include/bitcrypto/encoding/segwit.h"
#include "../../BitCrypto.Encoding/include/bitcrypto/encoding/taproot.h"

#if defined(BITCRYPTO_WITH_CUDA)
#include "../../BitCrypto.GPU/include/bitcrypto/gpu/ec_gpu.cuh"
#include "../../BitCrypto.GPU/include/bitcrypto/gpu/match_gpu.cuh"
#include <cuda_runtime.h>
#endif

using namespace bitcrypto;

static void fill_random_privs(std::vector<uint8_t>& privs){
    std::mt19937_64 rng(123456);
    for (size_t i=0;i<privs.size();i++) privs[i] = (uint8_t)rng();
    for (size_t i=0;i<privs.size(); i+=32) privs[i+31] |= 1; // evita zero
}

int main(int argc, char** argv){
    bool use_gpu = false;
    size_t N = 20000; // padrão
    bool bench_scalar = true;
    bool bench_match_h160 = true;
    bool bench_match_p2tr = true;
    std::string out_csv, out_md;

    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--gpu") use_gpu=true;
        else if (a=="--n" && i+1<argc){ N = (size_t)std::stoull(argv[++i]); }
        else if (a=="--only-scalar"){ bench_match_h160=false; bench_match_p2tr=false; }
        else if (a=="--only-match-h160"){ bench_scalar=false; bench_match_p2tr=false; }
        else if (a=="--only-match-p2tr"){ bench_scalar=false; bench_match_h160=false; }
        else if (a=="--csv" && i+1<argc){ out_csv = argv[++i]; }
        else if (a=="--md" && i+1<argc){ out_md = argv[++i]; }
        else if (a=="--help"){
            std::cout<<"Uso: BitCrypto.Bench [--gpu] [--n <itens>] [--only-scalar|--only-match-h160|--only-match-p2tr] [--csv <arq>] [--md <arq>]\n";
            return 0;
        }
    }

    std::cout<<"Itens: "<<N<<(use_gpu?" (GPU)":" (CPU)")<<"\n";
    std::vector<uint8_t> privs(N*32); fill_random_privs(privs);

    struct Row{ std::string name; double throughput; double seconds; Row(std::string n,double t,double s):name(std::move(n)),throughput(t),seconds(s){} };
    std::vector<Row> results;

    // 1) scalar_mul
    if (bench_scalar){
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!use_gpu){
            for (size_t i=0;i<N;i++){ U256 k = U256::from_be32(&privs[i*32]); auto Pub = Secp256k1::derive_pubkey(k); (void)Pub; }
        } else {
#if defined(BITCRYPTO_WITH_CUDA)
            uint8_t *d_priv=nullptr, *d_out=nullptr; size_t outsz = 33;
            cudaMalloc(&d_priv, privs.size()); cudaMemcpy(d_priv, privs.data(), privs.size(), cudaMemcpyHostToDevice);
            cudaMalloc(&d_out, N*outsz); gpu::scalar_mul_kernel<<< (int)((N+BITCRYPTO_CUDA_BLOCK_SIZE-1)/BITCRYPTO_CUDA_BLOCK_SIZE), BITCRYPTO_CUDA_BLOCK_SIZE >>>(d_priv, d_out, (int)N, 1);
            cudaDeviceSynchronize(); cudaFree(d_priv); cudaFree(d_out);
#else
            std::cerr<<"CUDA não habilitado.\n";
#endif
        }
        auto t1 = std::chrono::high_resolution_clock::now(); double secs = std::chrono::duration<double>(t1-t0).count();
        results.emplace_back("scalar_mul", (double)N/secs, secs);
        std::cout<<"scalar_mul: "<<(double)N/secs<<" ops/s ("<<secs<<" s)\n";
    }

    // 2) match HASH160
    if (bench_match_h160){
        uint8_t target_h160[20]; for (int i=0;i<20;i++) target_h160[i]=(uint8_t)i;
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!use_gpu){
            size_t hits=0;
            for (size_t i=0;i<N;i++){
                U256 k = U256::from_be32(&privs[i*32]);
                auto P = Secp256k1::derive_pubkey(k);
                uint8_t pub[65]; size_t plen=0; encode_pubkey(P, true, pub, plen);
                uint8_t h[20]; bitcrypto::hash::hash160(pub, plen, h);
                bool ok=true; for(int j=0;j<20;j++) if (h[j]!=target_h160[j]) { ok=false; break; } if (ok) hits++;
            }
            (void)hits;
        } else {
#if defined(BITCRYPTO_WITH_CUDA)
            uint8_t *d_priv=nullptr, *d_hits=nullptr, *d_target=nullptr;
            cudaMalloc(&d_priv, privs.size()); cudaMemcpy(d_priv, privs.data(), privs.size(), cudaMemcpyHostToDevice);
            cudaMalloc(&d_hits, N); cudaMemset(d_hits, 0, N);
            cudaMalloc(&d_target, 20); cudaMemcpy(d_target, target_h160, 20, cudaMemcpyHostToDevice);
            gpu::launch_match_p2pkh(d_priv, d_target, d_hits, (int)N, /*mode=*/1);
            cudaDeviceSynchronize(); cudaFree(d_priv); cudaFree(d_hits); cudaFree(d_target);
#else
            std::cerr<<"CUDA não habilitado.\n";
#endif
        }
        auto t1 = std::chrono::high_resolution_clock::now(); double secs = std::chrono::duration<double>(t1-t0).count();
        results.emplace_back("match_hash160", (double)N/secs, secs);
        std::cout<<"match HASH160: "<<(double)N/secs<<" keys/s ("<<secs<<" s)\n";
    }

    // 3) match P2TR
    if (bench_match_p2tr){
        uint8_t target32[32]; for (int i=0;i<32;i++) target32[i]=(uint8_t)i;
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!use_gpu){
            size_t hits=0;
            for (size_t i=0;i<N;i++){
                U256 k = U256::from_be32(&privs[i*32]);
                auto P = Secp256k1::derive_pubkey(k);
                uint8_t xonly[32]; bool neg=false; auto Peven = bitcrypto::encoding::normalize_even_y(P, xonly, neg);
                uint8_t t32b[32]; bitcrypto::hash::sha256_tagged("TapTweak", xonly, 32, t32b);
                U256 t = U256::from_be32(t32b); Secp256k1::scalar_mod_n(t);
                auto Qj = bitcrypto::Secp256k1::add(bitcrypto::Secp256k1::to_jacobian(Peven), bitcrypto::Secp256k1::scalar_mul(t, bitcrypto::Secp256k1::G()));
                auto Q = bitcrypto::Secp256k1::to_affine(Qj);
                uint8_t qx[32]; bool _neg=false; bitcrypto::encoding::normalize_even_y(Q, qx, _neg);
                bool ok=true; for(int j=0;j<32;j++) if (qx[j]!=target32[j]) { ok=false; break; } if (ok) hits++;
            }
            (void)hits;
        } else {
#if defined(BITCRYPTO_WITH_CUDA)
            uint8_t *d_priv=nullptr, *d_hits=nullptr, *d_target=nullptr;
            cudaMalloc(&d_priv, privs.size()); cudaMemcpy(d_priv, privs.data(), privs.size(), cudaMemcpyHostToDevice);
            cudaMalloc(&d_hits, N); cudaMemset(d_hits, 0, N);
            cudaMalloc(&d_target, 32); cudaMemcpy(d_target, target32, 32, cudaMemcpyHostToDevice);
            gpu::launch_match_p2tr(d_priv, d_target, d_hits, (int)N);
            cudaDeviceSynchronize(); cudaFree(d_priv); cudaFree(d_hits); cudaFree(d_target);
#else
            std::cerr<<"CUDA não habilitado.\n";
#endif
        }
        auto t1 = std::chrono::high_resolution_clock::now(); double secs = std::chrono::duration<double>(t1-t0).count();
        results.emplace_back("match_p2tr", (double)N/secs, secs);
        std::cout<<"match P2TR: "<<(double)N/secs<<" keys/s ("<<secs<<" s)\n";
    }

    // Emit reports
    if (!out_csv.empty()){
        FILE* f = fopen(out_csv.c_str(), "wb");
        if (f){
            fprintf(f, "name,throughput_ops_per_s,seconds,mode,N\n");
            for (auto& r: results) fprintf(f, "%s,%.6f,%.6f,%s,%llu\n", r.name.c_str(), r.throughput, r.seconds, use_gpu?"gpu":"cpu", (unsigned long long)N);
            fclose(f); std::cout<<"CSV salvo em "<<out_csv<<"\n";
        } else std::cerr<<"Falha ao abrir CSV: "<<out_csv<<"\n";
    }
    if (!out_md.empty()){
        FILE* f = fopen(out_md.c_str(), "wb");
        if (f){
            fprintf(f, "# BitCrypto Bench Report\n\n- Mode: %s\n- N: %llu\n\n", use_gpu?"GPU":"CPU", (unsigned long long)N);
            fprintf(f, "| Teste | Throughput (ops/s) | Tempo (s) |\n|---|---:|---:|\n");
            for (auto& r: results) fprintf(f, "| %s | %.2f | %.4f |\n", r.name.c_str(), r.throughput, r.seconds);
            fclose(f); std::cout<<"Markdown salvo em "<<out_md<<"\n";
        } else std::cerr<<"Falha ao abrir MD: "<<out_md<<"\n";
    }
    bitcrypto::secure_memzero(privs.data(), privs.size());
    return 0;
}
