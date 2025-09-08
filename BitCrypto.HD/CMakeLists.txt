add_library(BitCrypto.HD STATIC src/unity.cpp)
target_include_directories(BitCrypto.HD PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
)
target_link_libraries(BitCrypto.HD PUBLIC BitCrypto.Core BitCrypto.Hash BitCrypto.Encoding)
if (MSVC) target_compile_definitions(BitCrypto.HD PRIVATE _CRT_SECURE_NO_WARNINGS) endif()
