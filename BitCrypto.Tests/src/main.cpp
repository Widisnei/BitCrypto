#include <iostream>
#include <vector>
#include <string>
#include <bitcrypto/tx/miniscript.h>
#include <bitcrypto/psbt2/psbt_v2.h>
#include <bitcrypto/psbt2/psbt_v2_verify.h>

int main(){
    // thresh m>n deve falhar
    {
        std::vector<uint8_t> ws;
        if (bitcrypto::tx::miniscript_compile("thresh(3,02aa,03bb)", ws)){
            std::cerr<<"parse deveria falhar (thresh m>n)\n"; return 1;
        }
    }
    // or_i faltando vírgula
    {
        std::vector<uint8_t> ws;
        if (bitcrypto::tx::miniscript_compile("or_i(pk(02aa) pk(03bb))", ws)){
            std::cerr<<"parse deveria falhar (or_i sem vírgula)\n"; return 1;
        }
    }
    // PSBT amount=0
    {
        bitcrypto::psbt2::PSBT2 P; P.tx_version=2;
        bitcrypto::psbt2::PSBT2Out o; o.amount=0; P.outs.push_back(o);
        std::string err;
        if (bitcrypto::psbt2::verify_psbt2(P, err)){
            std::cerr<<"psbt2 verify deveria falhar (amount=0)\n"; return 1;
        }
    }
    std::cout<<"OK\n"; return 0;
}
