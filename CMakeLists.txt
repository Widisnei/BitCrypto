cmake_minimum_required(VERSION 3.23)

project(BitCrypto
  VERSION 2.5.0
  DESCRIPTION "BitCrypto: secp256k1 + Hashing + Tx/PSBT + CLIs (C++, CUDA opcional, sem deps externas)"
  LANGUAGES CXX)

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

enable_testing()

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
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.RNG/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Tx/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.PSBT/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.PSBTv2/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Sign/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Schnorr/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.Math/include
  ${CMAKE_CURRENT_SOURCE_DIR}/BitCrypto.EC/include
)

if(BITCRYPTO_ENABLE_CUDA)
  enable_language(CUDA)
  set(CMAKE_CUDA_ARCHITECTURES ${BITCRYPTO_CUDA_ARCH_LIST})
  add_compile_definitions(BITCRYPTO_WITH_CUDA=1)
  add_compile_options("$<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>")
endif()

macro(link_bitcrypto_common SUBDIR)
  if(EXISTS "${CMAKE_SOURCE_DIR}/${SUBDIR}/CMakeLists.txt")
    add_subdirectory(${SUBDIR})
    # O comando abaixo deve ser incluído nos CMakeLists.txt dos subdiretórios:
    # target_link_libraries(<TARGET> PRIVATE bitcrypto_common)
  endif()
endmacro()

link_bitcrypto_common(BitCrypto.Core)
link_bitcrypto_common(BitCrypto.Hash)
link_bitcrypto_common(BitCrypto.Encoding)
link_bitcrypto_common(BitCrypto.KDF)
link_bitcrypto_common(BitCrypto.HD)
link_bitcrypto_common(BitCrypto.Tx)
link_bitcrypto_common(BitCrypto.PSBT)
# PSBTv2 ainda em revisão
link_bitcrypto_common(BitCrypto.PSBTv2) # habilitado
link_bitcrypto_common(BitCrypto.Math)
link_bitcrypto_common(BitCrypto.Sign)
link_bitcrypto_common(BitCrypto.Schnorr)
link_bitcrypto_common(BitCrypto.RNG)
link_bitcrypto_common(BitCrypto.CLI)
link_bitcrypto_common(BitCrypto.HD.CLI)
link_bitcrypto_common(BitCrypto.PSBTCLI)
# link_bitcrypto_common(BitCrypto.PSBT2.CLI)
link_bitcrypto_common(BitCrypto.SchnorrCLI)
link_bitcrypto_common(BitCrypto.WSCLI)
link_bitcrypto_common(BitCrypto.MSCLI)
link_bitcrypto_common(BitCrypto.Bench)
link_bitcrypto_common(BitCrypto.BenchCLI)
link_bitcrypto_common(BitCrypto.Tests)
link_bitcrypto_common(BitCrypto.PSBT2.Tests)

if(BITCRYPTO_ENABLE_CUDA)
  link_bitcrypto_common(BitCrypto.GPU)
endif()
