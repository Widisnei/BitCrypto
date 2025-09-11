#pragma once
#include <cstdint>
#include <cstddef>
#if defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
  #include <ntstatus.h>
  #pragma comment(lib, "bcrypt.lib")
  #undef min
  #undef max
#endif
#include "base.h"
namespace bitcrypto {
inline bool rng_system(uint8_t* out, size_t n){
#if defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == STATUS_SUCCESS;
#else
    // Fallback simples para ambientes não Windows (apenas para desenvolvimento)
    // Em produção Windows/VS2022, o caminho CNG acima é utilizado.
    for (size_t i=0;i<n;i++) out[i]=(uint8_t)(i*131u + 89u); // NÃO criptograficamente seguro
    return true;
#endif
}
}
