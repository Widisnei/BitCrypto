#pragma once
#include <cstdint>
#include <cstddef>
#ifdef _WIN32
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#endif
namespace bitcrypto { namespace rng {
// Retorna true em caso de sucesso. Usa o RNG preferido do sistema (Windows CNG).
inline bool random_bytes(uint8_t* out, size_t n){
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(nullptr, (PUCHAR)out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st==0;
#else
    // Em outros sistemas, esta função pode ser estendida no futuro (mantemos compatibilidade com o alvo Windows).
    return false;
#endif
}
}}