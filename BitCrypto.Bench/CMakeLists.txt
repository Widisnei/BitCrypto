add_executable(BitCrypto.Bench src/bench.cpp)
target_include_directories(BitCrypto.Bench PRIVATE
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.GPU/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
)
target_link_libraries(BitCrypto.Bench PRIVATE BitCrypto.Core BitCrypto.Hash BitCrypto.Encoding)
target_link_libraries(BitCrypto.Bench PRIVATE bitcrypto_common)
if (TARGET BitCrypto.GPU)
  target_compile_definitions(BitCrypto.Bench PRIVATE BITCRYPTO_WITH_CUDA=1)
  target_link_libraries(BitCrypto.Bench PRIVATE BitCrypto.GPU)
endif()
if (MSVC)
    target_compile_definitions(BitCrypto.Bench PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
