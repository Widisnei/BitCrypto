add_library(BitCrypto.PSBTv2 STATIC src/unity.cpp)
target_include_directories(BitCrypto.PSBTv2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include ${CMAKE_SOURCE_DIR}/BitCrypto.Tx/include)
target_link_libraries(BitCrypto.PSBTv2 PUBLIC BitCrypto.Encoding BitCrypto.Tx)
target_link_libraries(BitCrypto.PSBTv2 PRIVATE bitcrypto_common)
