#pragma once
#include <string_view>
#include <bitcrypto/u256.h>
#include <bitcrypto/ec_secp256k1.h>

// Assinatura de mensagens genéricas conforme a especificação BIP-322
// https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki
namespace bitcrypto { namespace sign {

// Assinatura Schnorr (r,s) utilizada pelo BIP-322
struct Signature {
    uint8_t r[32];
    uint8_t s[32];
};

// Assina a mensagem arbitrária `msg` com a chave privada `priv`
Signature sign_message(const U256& priv, std::string_view msg);

// Verifica a assinatura `sig` da mensagem `msg` contra a chave pública `pub`
bool verify_message(const ECPointA& pub, std::string_view msg, const Signature& sig);

}} // namespace bitcrypto::sign
