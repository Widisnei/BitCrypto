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

#ifndef _WIN32
namespace detail {
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

#ifdef __linux__
enum class getrandom_result {
    completed,
    needs_fallback,
    error,
};

// Usa getrandom() para preencher o buffer; retorna se deve cair no fallback.
inline getrandom_result fill_from_getrandom(uint8_t* out, size_t n, size_t& off) {
    static constexpr size_t kGetrandomMax = 33554431u; // 32 MiB - 1, limite da syscall
    while (off < n) {
        size_t want = n - off;
        if (want > kGetrandomMax) {
            want = kGetrandomMax;
        }
        ssize_t r = ::getrandom(out + off, want, 0);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            if (errno == ENOSYS || errno == EINVAL || errno == EPERM) {
                return getrandom_result::needs_fallback;
            }
            return getrandom_result::error;
        }
        if (r == 0) {
            errno = EIO;
            return getrandom_result::needs_fallback;
        }
        off += static_cast<size_t>(r);
    }
    return getrandom_result::completed;
}
#endif // __linux__

// Lê de /dev/urandom respeitando limites de ssize_t e preservando errno.
inline bool fill_from_urandom(uint8_t* out, size_t n, size_t off) {
    if (off >= n) {
        return true;
    }
    int fd = -1;
    for (;;) {
        fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            break;
        }
        if (errno != EINTR && errno != EAGAIN) {
            return false;
        }
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
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            int err = errno;
            if (!close_fd_preserve(fd, err)) {
                return false;
            }
            return false;
        }
        if (!close_fd_preserve(fd, EIO)) {
            return false;
        }
        return false;
    }
    if (!close_fd_noerrno(fd)) {
        return false;
    }
    return true;
}
} // namespace detail
#endif
// Retorna true em caso de sucesso.
// No Windows usa o RNG preferido do sistema (CNG);
// em Unix tenta `getrandom()` e cai para `/dev/urandom` quando necessário.
inline bool random_bytes(uint8_t* out, size_t n) {
    // Rejeita ponteiros nulos quando há bytes a preencher, preservando a propagação de erro.
    if (out == nullptr) {
        if (n == 0) {
            return true;
        }
#ifdef _WIN32
        ::SetLastError(ERROR_INVALID_PARAMETER);
#else
        errno = EINVAL;
#endif
        return false;
    }
    if (n == 0) {
        return true;
    }
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st);
#else
    size_t off = 0;
#ifdef __linux__
    switch (detail::fill_from_getrandom(out, n, off)) {
    case detail::getrandom_result::completed:
        return true;
    case detail::getrandom_result::error:
        return false;
    case detail::getrandom_result::needs_fallback:
        break;
    }
#endif
    return detail::fill_from_urandom(out, n, off);
#endif
}
}} // ns
