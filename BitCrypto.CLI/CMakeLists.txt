add_executable(BitCrypto.CLI src/main.cpp)
target_include_directories(BitCrypto.CLI PRIVATE
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.GPU/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
)
target_link_libraries(BitCrypto.CLI PRIVATE BitCrypto.Core BitCrypto.Hash BitCrypto.Encoding BitCrypto.Sign BitCrypto.RNG BitCrypto.KDF BitCrypto.HD)
if (TARGET BitCrypto.GPU)
  target_compile_definitions(BitCrypto.CLI PRIVATE BITCRYPTO_WITH_CUDA=1)
  target_link_libraries(BitCrypto.CLI PRIVATE BitCrypto.GPU)
endif()
if (MSVC)
    target_compile_definitions(BitCrypto.CLI PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
