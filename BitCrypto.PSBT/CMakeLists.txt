add_library(BitCrypto.PSBT STATIC src/unity.cpp)
target_include_directories(BitCrypto.PSBT PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Sign/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Tx/include
)
target_link_libraries(BitCrypto.PSBT PUBLIC BitCrypto.Hash BitCrypto.Core BitCrypto.Sign BitCrypto.Encoding BitCrypto.Tx)
if (MSVC)
    target_compile_definitions(BitCrypto.PSBT PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
