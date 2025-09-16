#pragma once
#include <cstdint>
#include <cstddef>
#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #if defined(_MSC_VER)
    #pragma comment(lib, "bcrypt.lib")
  #endif
  #undef min
  #undef max
#else
  // Dependência: fontes de entropia do sistema (`getrandom()` ou `/dev/urandom`).
  // O descritor é aberto com `O_CLOEXEC`, chamadas repetem em caso de EINTR/EAGAIN
  // e, ao receber ENOSYS/EINVAL/EPERM de `getrandom()`, o código recai para
  // `/dev/urandom`.  Erros são propagados ao chamador.
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <sys/types.h> // ssize_t
  #include <limits>
  #ifdef __linux__
    #include <sys/random.h>
  #endif
#endif
namespace bitcrypto { namespace rng {
// Retorna true em caso de sucesso.
// No Windows usa o RNG preferido do sistema (CNG);
// em Unix tenta `getrandom()` e cai para `/dev/urandom` quando necessário.
inline bool random_bytes(uint8_t* out, size_t n) {
    if (n == 0) {
        return true;
    }
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st);
#else
    size_t off = 0;
#ifdef __linux__
    static constexpr size_t kGetrandomMax = 33554431u; // 32 MiB - 1, limite da syscall
    // Usa getrandom() em sistemas Linux; se indisponível, cai para /dev/urandom.
    while (off < n) {
        size_t want = n - off;
        if (want > kGetrandomMax) {
            want = kGetrandomMax;
        }
        ssize_t r = ::getrandom(out + off, want, 0);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (errno == ENOSYS || errno == EINVAL || errno == EPERM) break; // fallback
            return false;
        }
        off += static_cast<size_t>(r);
    }
    if (off == n) return true;
#endif
    if (off >= n) {
        return true;
    }
    // Fallback genérico: leitura de /dev/urandom.
    int fd = -1;
    for (;;) {
        fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) break;
        if (errno != EINTR && errno != EAGAIN) return false;
    }
    const size_t max_chunk = static_cast<size_t>(std::numeric_limits<ssize_t>::max());
    while (off < n) {
        size_t want = n - off;
        if (want > max_chunk) {
            want = max_chunk;
        }
        ssize_t r = ::read(fd, out + off, want);
        if (r > 0) {
            off += static_cast<size_t>(r);
            continue;
        }
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            int err = errno;
            if (::close(fd) != 0) {
                return false; // errno já reflete a falha em close()
            }
            errno = err;
            return false;
        }
        // `read()` retornou 0: `/dev/urandom` não entregou dados; sinaliza erro.
        if (::close(fd) != 0) {
            return false;
        }
        errno = EIO;
        return false;
    }
    if (::close(fd) != 0) {
        return false;
    }
    return true;
#endif
}
}} // ns
