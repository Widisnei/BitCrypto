add_library(BitCrypto.GPU STATIC
    src/kernels.cu
    src/match.cu
)
target_include_directories(BitCrypto.GPU PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Core/include
    ${CMAKE_SOURCE_DIR}/BitCrypto.Hash/include
)
set_target_properties(BitCrypto.GPU PROPERTIES CUDA_ARCHITECTURES 86)
target_link_libraries(BitCrypto.GPU PUBLIC BitCrypto.Core)
target_link_libraries(BitCrypto.GPU PRIVATE bitcrypto_common)
