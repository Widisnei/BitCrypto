#pragma once
// bitcrypto/utils/safe.h
// Utilidades de segurança (tempo constante e limpeza de memória).

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bitcrypto { namespace utils {

// Comparação em tempo constante (retorna true se iguais).
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n){
    uint8_t d = 0;
    for (size_t i=0;i<n;i++) d |= (uint8_t)(a[i] ^ b[i]);
    // Converte para bool sem curto-circuito
    return d == 0;
}

// Limpeza "best-effort" de memória (evita otimização do compilador).
inline void secure_wipe(void* p, size_t n){
#if defined(_MSC_VER)
    volatile uint8_t* vp = (volatile uint8_t*)p;
    for (size_t i=0;i<n;i++) vp[i]=0;
#else
    std::memset(p, 0, n);
    asm volatile("" : : "r"(p) : "memory");
#endif
}

}} // ns
