add_executable(BitCrypto.Core.MSM tests_msm_pippenger.cpp)
target_link_libraries(BitCrypto.Core.MSM PRIVATE bitcrypto_common)
add_test(NAME BitCrypto.Core.MSM COMMAND BitCrypto.Core.MSM)
