add_executable(BitCrypto.Tests src/tests.cpp)
target_include_directories(BitCrypto.Tests PRIVATE
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
)
target_link_libraries(BitCrypto.Tests PRIVATE BitCrypto.Core BitCrypto.Hash BitCrypto.Encoding BitCrypto.Sign BitCrypto.HD BitCrypto.KDF)
if (MSVC)
    target_compile_definitions(BitCrypto.Tests PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
