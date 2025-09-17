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
#ifndef _WIN32
namespace {
// Fecha descritores preservando errno original em caminhos de erro.
inline bool close_fd_preserve(int fd, int restore_errno) {
    if (fd < 0) {
        return true;
    }
    int rc;
    do {
        rc = ::close(fd);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        return false;
    }
    errno = restore_errno;
    return true;
}

// Fecha descritores restaurando errno anterior em caminhos de sucesso.
inline bool close_fd_noerrno(int fd) {
    if (fd < 0) {
        return true;
    }
    int saved_errno = errno;
    int rc;
    do {
        rc = ::close(fd);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        return false;
    }
    errno = saved_errno;
    return true;
}
} // namespace
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
        if (r == 0) {
            errno = EIO;
            break; // força fallback para /dev/urandom
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
            if (!close_fd_preserve(fd, err)) {
                return false;
            }
            return false;
        }
        // `read()` retornou 0: `/dev/urandom` não entregou dados; sinaliza erro.
        if (!close_fd_preserve(fd, EIO)) {
            return false;
        }
        return false;
    }
    if (!close_fd_noerrno(fd)) {
        return false;
    }
    return true;
#endif
}
}} // ns
