add_executable(BitCrypto.MSCLI src/main.cpp)
target_include_directories(BitCrypto.MSCLI PUBLIC ${CMAKE_SOURCE_DIR}/BitCrypto.Tx/include ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include)
target_link_libraries(BitCrypto.MSCLI PRIVATE BitCrypto.Tx BitCrypto.Hash BitCrypto.Encoding)
target_link_libraries(BitCrypto.MSCLI PRIVATE bitcrypto_common)
