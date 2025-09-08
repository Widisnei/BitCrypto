add_library(BitCrypto.Tx STATIC src/unity.cpp)
target_include_directories(BitCrypto.Tx PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
)
target_link_libraries(BitCrypto.Tx PUBLIC BitCrypto.Hash BitCrypto.Core BitCrypto.Encoding)
if (MSVC)
    target_compile_definitions(BitCrypto.Tx PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
