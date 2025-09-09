cmake_minimum_required(VERSION 3.20)
project(BitCrypto.PSBT2.Tests LANGUAGES CXX)
add_executable(BitCrypto.PSBT2.Tests src/tests_psbt2.cpp)
target_include_directories(BitCrypto.PSBT2.Tests PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(BitCrypto.PSBT2.Tests PRIVATE BitCrypto.Tx BitCrypto.Hash BitCrypto.Encoding BitCrypto.PSBTv2 BitCrypto.Core)
target_link_libraries(BitCrypto.PSBT2.Tests PRIVATE bitcrypto_common)

add_test(NAME BitCrypto.PSBT2.Tests COMMAND BitCrypto.PSBT2.Tests)
