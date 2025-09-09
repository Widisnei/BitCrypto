add_library(BitCrypto.Encoding STATIC src/unity.cpp)
target_include_directories(BitCrypto.Encoding PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
)
target_link_libraries(BitCrypto.Encoding PUBLIC BitCrypto.Hash BitCrypto.Core)
target_link_libraries(BitCrypto.Encoding PRIVATE bitcrypto_common)
