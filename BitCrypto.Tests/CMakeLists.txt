add_executable(BitCrypto.Tests src/tests.cpp)
target_include_directories(BitCrypto.Tests PRIVATE
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Tx/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.PSBT/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.PSBTv2/include
)
target_link_libraries(BitCrypto.Tests PRIVATE BitCrypto.Core BitCrypto.Hash BitCrypto.Encoding BitCrypto.Tx BitCrypto.PSBT BitCrypto.PSBTv2 BitCrypto.Sign BitCrypto.HD BitCrypto.KDF)
target_link_libraries(BitCrypto.Tests PRIVATE bitcrypto_common)
if (MSVC)
    target_compile_definitions(BitCrypto.Tests PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_test(NAME BitCrypto.Tests COMMAND BitCrypto.Tests)
