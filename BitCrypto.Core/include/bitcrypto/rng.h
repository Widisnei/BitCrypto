#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#if defined(_WIN32)
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#endif
#include "base.h"
namespace bitcrypto {
inline bool rng_system(uint8_t* out, size_t n){
#if defined(_WIN32)
    // STATUS_SUCCESS (0) indica sucesso na API CNG
    return BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    // Fallback simples para ambientes não Windows (apenas para desenvolvimento)
    // Em produção Windows/VS2022, o caminho CNG acima é utilizado.
    for (size_t i=0;i<n;i++) out[i]=(uint8_t)(i*131u + 89u); // NÃO criptograficamente seguro
    return true;
#endif
}
}
