add_library(BitCrypto.Sign STATIC src/unity.cpp)
target_include_directories(BitCrypto.Sign PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include)
target_link_libraries(BitCrypto.Sign PUBLIC BitCrypto.Core BitCrypto.Hash)
if (MSVC) target_compile_definitions(BitCrypto.Sign PRIVATE _CRT_SECURE_NO_WARNINGS) endif()
