add_executable(BitCrypto.PSBTCLI src/main.cpp)
target_include_directories(BitCrypto.PSBTCLI PUBLIC ${CMAKE_SOURCE_DIR}/BitCrypto.PSBTv2/include ${CMAKE_SOURCE_DIR}/BitCrypto.Tx/include ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include)
target_link_libraries(BitCrypto.PSBTCLI PRIVATE BitCrypto.PSBTv2 BitCrypto.Tx BitCrypto.Hash BitCrypto.Encoding)
