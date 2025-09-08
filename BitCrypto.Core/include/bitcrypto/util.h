#pragma once
#include <cstddef>
#include <thread>

namespace bitcrypto {
inline void secure_zero(void* p, size_t n){
    volatile unsigned char* v = reinterpret_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}
inline unsigned cpu_threads(){
    unsigned t = std::thread::hardware_concurrency();
    return t ? t : 1u;
}
} // namespace bitcrypto
