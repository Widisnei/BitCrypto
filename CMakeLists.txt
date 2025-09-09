cmake_minimum_required(VERSION 3.23)

# -----------------------------------------------------------------------------
# Project metadata
# -----------------------------------------------------------------------------
project(BitCrypto
  VERSION 2.5.0
  DESCRIPTION "BitCrypto: secp256k1 + Hashing + Tx/PSBT + CLIs (C++, CUDA opcional, sem deps externas)"
  LANGUAGES CXX)

# -----------------------------------------------------------------------------
# Build type and language standards
# -----------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

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
option(BITCRYPTO_ENABLE_LTO   "Habilitar IPO/LTO (Release/RelWithDebInfo)" ON)
option(BITCRYPTO_ENABLE_CUDA  "Compilar módulos CUDA" OFF)
set(BITCRYPTO_CUDA_ARCH_LIST "86" CACHE STRING "Lista de SMs (ex.: 86; 89; 90)")
set(BITCRYPTO_VERSION_STRING "${PROJECT_VERSION}" CACHE STRING "" FORCE)

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
add_library(bitcrypto_common INTERFACE)
target_compile_definitions(bitcrypto_common INTERFACE
  NOMINMAX _CRT_SECURE_NO_WARNINGS
  BITCRYPTO_VERSION="${BITCRYPTO_VERSION_STRING}")
target_include_directories(bitcrypto_common INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Core/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Hash/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Encoding/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.KDF/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.HD/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Tx/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.PSBT/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.PSBTv2/include/bitcrypto
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Math/include/bitcrypto
)

# -----------------------------------------------------------------------------
# Optional CUDA configuration
# -----------------------------------------------------------------------------
if(BITCRYPTO_ENABLE_CUDA)
  enable_language(CUDA)
  set(CMAKE_CUDA_ARCHITECTURES ${BITCRYPTO_CUDA_ARCH_LIST})
  add_compile_definitions(BITCRYPTO_WITH_CUDA=1)
  add_compile_options("$<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>")
endif()

# -----------------------------------------------------------------------------
# Subdirectories
# -----------------------------------------------------------------------------
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

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Sign/CMakeLists.txt")
  add_subdirectory(BitCrypto.Sign)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.RNG/CMakeLists.txt")
  add_subdirectory(BitCrypto.RNG)
endif()

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

if(EXISTS "${CMAKE_SOURCE_DIR}/BitCrypto.Bench/CMakeLists.txt")
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

if(BITCRYPTO_ENABLE_CUDA)
  add_subdirectory(BitCrypto.GPU)
endif()
