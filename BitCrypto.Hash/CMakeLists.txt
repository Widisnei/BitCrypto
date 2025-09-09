add_library(BitCrypto.Hash STATIC src/unity.cpp)
target_include_directories(BitCrypto.Hash PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(BitCrypto.Hash PRIVATE bitcrypto_common)
