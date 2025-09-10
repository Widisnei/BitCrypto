# BitCrypto — Arquitetura de Módulos (v2.5.0)

## Visão Geral

BitCrypto é uma biblioteca modular escrita em C++/CUDA para operações criptográficas ligadas ao ecossistema Bitcoin.  A versão 2.5.0 consolida os marcos anteriores e expande a biblioteca com otimizações de curva, um conjunto completo de ferramentas de transação/PSBT e suporte opcional a GPU.  A filosofia do projeto permanece inalterada: **nenhuma dependência externa**, **completude**, **não‑redundância** e **compatibilidade** com Visual Studio 2022/Windows 11 x64 e CUDA 13.

Os principais módulos são:

- **BitCrypto.Core** — fornece primitivas de aritmética: tipos `U256`, campos `Fp` (p=2^256−2^32−977) e `Fn` (ordem n da curva), operações de ponto em coordenadas Jacobianas e utilitários de segurança.  Inclui otimizações de multiplicação escalar com **wNAF (janela 4)** e pré‑cálculo de G para operações `s·G`, **MSM Pippenger** com janelas adaptativas e contexto de **precompute**, rotinas de **endomorphism** e **Shamir's trick** para decompor escalares e combinar `a·P + b·G`, além de uma ladder constante para `s·P` gerais.
- **BitCrypto.Hash** — implementa funções de hash `SHA‑256` (com unrolling moderado) e `SHA‑512`, `RIPEMD‑160`, HMACs (`HMAC‑SHA256`/`HMAC‑SHA512`), derivação de chave **PBKDF2‑HMAC‑SHA512**, `HASH160` e `sha256_tagged` para assinaturas Schnorr/Taproot.
- **BitCrypto.Encoding** — trata da representação textual de chaves e endereços: codificadores Base58/Base58Check, Bech32/Bech32m, WIF (privada), conversão entre formatos de endereço (**P2PKH**, **P2WPKH**, **P2TR**) e detecção automática de tipo de endereço.  Inclui codificação e decodificação de **xprv/xpub** (BIP‑32).
- **BitCrypto.KDF** — abstração de geração de entropia utilizando a API nativa do Windows (`BCryptGenRandom`), sem dependências de bibliotecas de terceiros.
- **BitCrypto.HD** — suporte a carteiras hierárquicas determinísticas conforme **BIP‑32**, **BIP‑39** e **BIP‑44**: derivação de sementes a partir de *mnemonics*, `CKDpriv`/`CKDpub` (hardened e não‑hardened), serialização/deserialização de xprv/xpub e geração de listas de palavras para ambientes de teste.
- **BitCrypto.Sign** — implementa assinaturas determinísticas **ECDSA** (RFC6979) com codificação DER estrita e normalização *low‑S*, e **Schnorr** (BIP‑340) com checagens de chave e normalização `x‑only` (Y par).  Inclui verificação das assinaturas, cálculo de `sha256_tagged` e agregação de chaves, *nonces* e assinaturas parciais **MuSig2** via MSM Pippenger.
- **BitCrypto.Tx** — fornece estruturas e utilitários para transações Bitcoin legadas e SegWit/Taproot: tipos `Transaction/TxIn/TxOut`, *varint*, construção de scripts (`scriptSig` e `witness`), serialização para hex, cálculo de `txid/wtxid` e implementação completa de **sighash** (legacy/BIP‑143/BIP‑341 key‑path) com suporte às flags **ALL**, **NONE**, **SINGLE** e **ANYONECANPAY**.
- **BitCrypto.PSBT** e **BitCrypto.PSBTv2** — módulos para criação, parsing, assinatura e finalização de Partially Signed Bitcoin Transactions (PSBT) nas versões v0 (BIP‑174) e v2 (BIP‑370).  Preservam pares desconhecidos (unknown K/V), suportam testemunhas de Taproot, geram resumos *pretty* e exposições de witness (`witness_items`, `witness_sizes`, `tap_control_block_depth`, `witness_preview`).
- **BitCrypto.MSCLI** e **BitCrypto.PSBTCLI** — ferramentas de linha de comando para trabalhar com Miniscript e PSBT: geração e análise de expresões Miniscript (`and`/`or`/`thresh`, timelocks), pareamento determinístico de TapTree via hash, inferência de `nLockTime`/`nSequence` (`--infer‑timelocks`), criação/assinatura/finalização de PSBTs e impressão de witness e campos avançados.
- **BitCrypto.GPU** — kernels em CUDA 13 para multiplicação escalar e busca de chaves/endereços (`match` de **HASH160** e **P2TR**) em lote, com *launch bounds* ajustáveis e janelas wNAF para alto desempenho.  A GPU é usada apenas quando traz ganhos significativos (regra de não‑redundância).
- **BitCrypto.Tests** e **BitCrypto.Bench** — suíte de testes unitários e de propriedade, com vetores canônicos para todas as rotas, casos negativos e verificação constante de integridade; e ferramentas de benchmark que medem throughput de operações (CPU/GPU) com exportação para CSV/Markdown.

## Diretrizes de Arquitetura

- **Sem dependências externas**: a biblioteca utiliza apenas C++ padrão, APIs nativas do Windows e CUDA; não depende de OpenSSL, libsodium ou qualquer outra biblioteca de terceiros.
- **Completude e não‑redundância**: todas as rotas são implementadas sem *stubs*; a duplicação de código só ocorre quando versões CPU e GPU coexistem por razões de desempenho.
- **Const‑time**: operações que manipulam dados sensíveis evitam ramos e acessos de memória dependentes do segredo, usando técnicas como `cswap/cmov`.
- **Documentação em PT‑BR**: comentários e documentos são escritos em português e explicam o racional e os invariantes de cada componente.
- **Guard‑rails e manifesto**: scripts em `tools/guardrails` garantem que o pacote seja entregue sem dependências externas, com manifesto e metadados atualizados; tokens de novas features (wNAF, witness preview, etc.) são validados a cada release.

Esta estrutura modular e as diretrizes acima permitem que o BitCrypto evolua de forma incremental sem comprometer a robustez, a clareza e a auditabilidade do código.