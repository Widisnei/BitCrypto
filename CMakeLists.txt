cmake_minimum_required(VERSION 3.23)

# -----------------------------------------------------------------------------
# Project metadata
# -----------------------------------------------------------------------------
# Define the project with a semantic version and brief description.  CUDA is an
# optional language for GPU acceleration; most users will build the CPU-only
# version by default.
project(BitCrypto
  VERSION 2.5.0
  DESCRIPTION "BitCrypto: secp256k1 + Hashing + Tx/PSBT + CLIs (C++, CUDA opcional, sem deps externas)"
  LANGUAGES CXX)

# -----------------------------------------------------------------------------
# Build type and language standards
# -----------------------------------------------------------------------------
# Default to RelWithDebInfo if no build type is specified by the user or CI.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
endif()

# Require C++17 and disable compiler extensions. CUDA is enabled only when
# BITCRYPTO_ENABLE_CUDA is ON (see below). These settings ensure modern C++
# language features while preserving portability across compilers.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Optionally treat warnings as errors.  This is disabled by default but can be
# enabled in CI or by passing -DBITCRYPTO_STRICT_WARNINGS=ON.
option(BITCRYPTO_STRICT_WARNINGS "Tratar warnings como erro" OFF)
if(BITCRYPTO_STRICT_WARNINGS)
  if(MSVC)
    add_compile_options(/WX)
  else()
    add_compile_options(-Werror)
  endif()
endif()

# -----------------------------------------------------------------------------
# Feature toggles
# -----------------------------------------------------------------------------
# BITCRYPTO_ENABLE_LTO: Enable link-time optimization (IPO/LTO) in Release and
# RelWithDebInfo builds.  Enabled by default.
option(BITCRYPTO_ENABLE_LTO   "Habilitar IPO/LTO (Release/RelWithDebInfo)" ON)

# BITCRYPTO_ENABLE_CUDA: Compile GPU modules.  Off by default; enable if you
# have a CUDA-capable device and want GPU acceleration.
option(BITCRYPTO_ENABLE_CUDA  "Compilar módulos CUDA" OFF)

# List of CUDA compute capabilities to target; default is 86 (NVIDIA Ampere).
set(BITCRYPTO_CUDA_ARCH_LIST "86" CACHE STRING "Lista de SMs (ex.: 86; 89; 90)")

# Expose the project version to code via a preprocessor macro.  This can be
# inspected at runtime and used in diagnostics or manifest generation.
set(BITCRYPTO_VERSION_STRING "${PROJECT_VERSION}" CACHE STRING "" FORCE)

# Apply link-time optimisation if enabled.  This checks that the current
# toolchain supports IPO before enabling it; otherwise, it silently skips.
if(BITCRYPTO_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT _ipo_ok OUTPUT _ipo_msg)
  if(_ipo_ok)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE         ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO  ON)
  endif()
endif()

# -----------------------------------------------------------------------------
# Common library for definitions and include paths
# -----------------------------------------------------------------------------
# Define an INTERFACE library to share common definitions and include
# directories across all modules.  This avoids repeating include paths in
# every subproject and ensures that BITCRYPTO_VERSION is defined globally.
add_library(bitcrypto_common INTERFACE)
target_compile_definitions(bitcrypto_common INTERFACE
  NOMINMAX _CRT_SECURE_NO_WARNINGS
  BITCRYPTO_VERSION="${BITCRYPTO_VERSION_STRING}")
target_include_directories(bitcrypto_common INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Core/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Hash/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Encoding/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.KDF/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.HD/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Tx/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.PSBT/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.PSBTv2/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Math/include
)

# -----------------------------------------------------------------------------
# Optional CUDA configuration
# -----------------------------------------------------------------------------
if(BITCRYPTO_ENABLE_CUDA)
  enable_language(CUDA)
  # Target specific compute capabilities; multiple values can be separated by
  # semicolons.  Example: "86;89".  Users can override this from the command
  # line or via CMakePresets.json.
  set(CMAKE_CUDA_ARCHITECTURES ${BITCRYPTO_CUDA_ARCH_LIST})
  add_compile_definitions(BITCRYPTO_WITH_CUDA=1)
  # Relax constexpr restrictions in CUDA to improve compile-time performance.
  add_compile_options("$<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>")
endif()

# -----------------------------------------------------------------------------
# Subdirectories
# -----------------------------------------------------------------------------
# Always include these core modules.  CUDA-specific modules are added only if
# BITCRYPTO_ENABLE_CUDA is ON.  The ordering reflects module dependencies.
if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Core/CMakeLists.txt")
  add_subdirectory(BitCrypto.Core)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Hash/CMakeLists.txt")
  add_subdirectory(BitCrypto.Hash)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/CMakeLists.txt")
  add_subdirectory(BitCrypto.Encoding)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.KDF/CMakeLists.txt")
  add_subdirectory(BitCrypto.KDF)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.HD/CMakeLists.txt")
  add_subdirectory(BitCrypto.HD)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Tx/CMakeLists.txt")
  add_subdirectory(BitCrypto.Tx)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.PSBT/CMakeLists.txt")
  add_subdirectory(BitCrypto.PSBT)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.PSBTv2/CMakeLists.txt")
  add_subdirectory(BitCrypto.PSBTv2)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Math/CMakeLists.txt")
  add_subdirectory(BitCrypto.Math)
endif()

# Signatures, RNG and extra utilities
if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Sign/CMakeLists.txt")
  add_subdirectory(BitCrypto.Sign)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.RNG/CMakeLists.txt")
  add_subdirectory(BitCrypto.RNG)
endif()

# Command-line interfaces
if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.CLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.CLI)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.HD.CLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.HD.CLI)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.PSBTCLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.PSBTCLI)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.PSBT2.CLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.PSBT2.CLI)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.WSCLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.WSCLI)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.MSCLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.MSCLI)
endif()

# Benchmarks and tests
if(EXISTS "${CMAKE_SOURCE_DIR}/BBitCrypto.Bench/CMakeLists.txt")
  add_subdirectory(BitCrypto.Bench)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.BenchCLI/CMakeLists.txt")
  add_subdirectory(BitCrypto.BenchCLI)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Tests/CMakeLists.txt")
  add_subdirectory(BitCrypto.Tests)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.PSBT2.Tests/CMakeLists.txt")
  add_subdirectory(BitCrypto.PSBT2.Tests)
endif()

# GPU acceleration (optional)
if(BITCRYPTO_ENABLE_CUDA)
  add_subdirectory(BitCrypto.GPU)
endif()
