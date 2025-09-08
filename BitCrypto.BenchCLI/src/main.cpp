#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <bitcrypto/hash/sha256_cpu.h>
#ifdef __CUDACC__
#include <cuda_runtime.h>
#include <bitcrypto/gpu/sha256_gpu.cuh>
#endif
static void fill_pattern(std::vector<uint8_t>& buf){ for (size_t i=0;i<buf.size(); ++i) buf[i] = uint8_t((0xA5 + 31*i) & 0xFF); }
int main(int argc, char** argv){
    try{
        bool cpu=false, gpu=false; size_t bytes=0; int iters=1;
        for (int i=1;i<argc;i++){ std::string a=argv[i];
            if (a=="--cpu-sha256-bytes" && i+1<argc){ cpu=true; bytes=std::stoull(argv[++i]); }
            else if (a=="--gpu-sha256-bytes" && i+1<argc){ gpu=true; bytes=std::stoull(argv[++i]); }
            else if (a=="--iters" && i+1<argc){ iters=std::stoi(argv[++i]); }
            else { std::cerr<<"Uso: BitCrypto.BenchCLI (--cpu-sha256-bytes N | --gpu-sha256-bytes N) [--iters M]\n"; return 2; }
        }
        if (!cpu && !gpu){ std::cerr<<"Selecione --cpu-sha256-bytes ou --gpu-sha256-bytes\n"; return 2; }
        if (bytes==0){ std::cerr<<"Bytes deve ser > 0\n"; return 2; }
        if (gpu && (bytes % 64)!=0){ std::cerr<<"Para --gpu-sha256-bytes N deve ser múltiplo de 64 (1 bloco/64B por thread)\n"; return 2; }
        if (cpu){
            std::vector<uint8_t> buf(bytes); fill_pattern(buf); uint8_t out[32];
            auto t0=std::chrono::high_resolution_clock::now();
            for (int it=0; it<iters; ++it){ bitcrypto::hash::sha256(buf.data(), buf.size(), out); }
            auto t1=std::chrono::high_resolution_clock::now(); std::chrono::duration<double> dt=t1-t0;
            double total=double(bytes)*iters; double mbps=(total/(1024.0*1024.0))/dt.count();
            std::cout<<std::fixed<<std::setprecision(2);
            std::cout<<"cpu_sha256_bytes="<<bytes<<" iters="<<iters<<" time_s="<<dt.count()<<" throughput_MBps="<<mbps<<"\n";
            std::cout<<"out32="; for (int i=0;i<32;i++) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)out[i]; std::cout<<"\n"; return 0;
        }
#ifdef __CUDACC__
        if (gpu){
            std::vector<uint8_t> host(bytes); fill_pattern(host); size_t nmsgs=bytes/64;
            uint8_t *d_in=nullptr,*d_out=nullptr; cudaMalloc(&d_in, bytes); cudaMalloc(&d_out, nmsgs*32);
            cudaMemcpy(d_in, host.data(), bytes, cudaMemcpyHostToDevice);
            dim3 bs(256), gs((unsigned)((nmsgs + bs.x - 1)/bs.x));
            auto t0=std::chrono::high_resolution_clock::now();
            for (int it=0; it<iters; ++it){ bitcrypto::gpu::sha256_many_64B<<<gs, bs>>>(d_in, d_out, nmsgs); cudaDeviceSynchronize(); }
            auto t1=std::chrono::high_resolution_clock::now(); std::vector<uint8_t> out(nmsgs*32);
            cudaMemcpy(out.data(), d_out, out.size(), cudaMemcpyDeviceToHost); cudaFree(d_in); cudaFree(d_out);
            std::chrono::duration<double> dt=t1-t0; double total=double(bytes)*iters; double mbps=(total/(1024.0*1024.0))/dt.count();
            std::cout<<std::fixed<<std::setprecision(2);
            std::cout<<"gpu_sha256_bytes="<<bytes<<" iters="<<iters<<" time_s="<<dt.count()<<" throughput_MBps="<<mbps<<"\n";
            std::cout<<"out_first32="; for (int i=0;i<32;i++) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)out[i]; std::cout<<"\n"; return 0;
        }
#else
        if (gpu){ std::cerr<<"Compilação sem CUDA; modo GPU indisponível.\n"; return 3; }
#endif
        return 0;
    }catch(const std::exception& e){ std::cerr<<"erro: "<<e.what()<<"\n"; return 2; }
}