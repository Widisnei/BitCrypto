add_executable(BitCrypto.Schnorr.MuSig2 tests_musig2.cpp)
target_link_libraries(BitCrypto.Schnorr.MuSig2 PRIVATE bitcrypto_common)
add_test(NAME BitCrypto.Schnorr.MuSig2 COMMAND BitCrypto.Schnorr.MuSig2)
