add_executable(BitCrypto.HD.CLI src/hd_main.cpp)
target_include_directories(BitCrypto.HD.CLI PRIVATE
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Encoding/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.KDF/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.HD/include
)
target_link_libraries(BitCrypto.HD.CLI PRIVATE BitCrypto.Core BitCrypto.Hash BitCrypto.Encoding BitCrypto.KDF BitCrypto.HD)
if (MSVC)
    target_compile_definitions(BitCrypto.HD.CLI PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
