# Descrição dos Componentes do BitCrypto

Este documento detalha os principais módulos que compõem o projeto **BitCrypto** na versão 2.5.0.  Seu objetivo é oferecer uma visão rápida sobre o que cada componente faz, quais algoritmos ou padrões de implementação utiliza e como os módulos se integram.  Para uma análise arquitetural completa, consulte também `ARQUITETURA.md`.

## Core (`BitCrypto.Core`)

O núcleo da biblioteca fornece os tipos e operações fundamentais:

- **Inteiros e campos finitos**: tipos `U256` e representações de elementos em `F_p` e `F_n`, com redução pseudo‑Mersenne para o primo `p = 2^256 − 2^32 − 977` e a ordem `n` da curva secp256k1.  As operações (`add/sub/mul/sqr/inv/sqrt`) são implementadas em C++ puro, em tempo constante quando lidam com dados secretos.
- **Pontos na curva**: implementação de pontos em coordenadas Jacobianas para secp256k1, com adição e duplicação otimizadas.  Para multiplicação escalar, o módulo oferece duas estratégias: uma *ladder* constante generalizada (para `s·P`) e **wNAF (janela 4)** com pré‑cálculo específico para `s·G`, reduzindo tempo e memória na inicialização【481458509835048†L575-L593】.
- **Contexto de pré‑cálculo**: algoritmos otimizados dependem de tabelas de pontos precomputados.  Esses dados são mantidos em um contexto explicitamente inicializado, que deve ser passado às funções quando se deseja alto desempenho.  Sem contexto, a biblioteca recorre à ladder constante, mantendo a compatibilidade【411223492370334†L14-L24】.
- **Utilitários**: funções de verificação de validade, conversão e segurança (por exemplo, `secure_memzero`), além de wrappers para operações seguras em memória.

## Hash (`BitCrypto.Hash`)

Fornece funções criptográficas de dispersão e HMAC:

- **SHA‑256 e SHA‑512**: implementações escritas do zero, com unrolling manual moderado e interfaces de atualização incremental.
- **RIPEMD‑160** e combinações (`HASH160`, `HASH256`, `tagged_hash`) para uso em endereços Bitcoin e assinaturas Schnorr (BIP‑340/341).
- **HMAC** (`HMAC‑SHA256`/`HMAC‑SHA512`) e **PBKDF2‑HMAC‑SHA512** para derivação de chaves e geração de nonces determinísticas (RFC 6979).
- **Funções auxiliares** para hashing etiquetado (tagged hash) e conversão de mensagens.

## Encoding (`BitCrypto.Encoding`)

Responsável por serialização e codificação de chaves e endereços:

- **Base58/Base58Check**: codificação e decodificação, incluindo checagem de checksum e detecção automática de tamanho.
- **Bech32/Bech32m**: suporte a endereços SegWit v0/v1, com validação do polinômio BCH.
- **WIF (Wallet Import Format)**: serialização de chaves privadas, com bits de compressão.
- **Detectores e conversores**: funções para detectar o tipo de endereço (P2PKH, P2WPKH, P2TR) e construir scriptPubKey correspondente.
- **Serialização de xprv/xpub**: BIP‑32, com codificação para Base58Check.

## KDF & HD (`BitCrypto.KDF` e `BitCrypto.HD`)

- **RNG**: wrapper para `BCryptGenRandom` do Windows, garantindo geração de entropia sem dependências externas.
- **BIP‑32/39/44**: derivação de HD wallets — geração de seeds a partir de *mnemonics*, derivação de chaves privadas/públicas (hardened e não‑hardened), serialização de caminhos, importação/exportação de xprv/xpub e suporte a diferentes *path* (`m/44’/0’/0’/...`).

## Sign (`BitCrypto.Sign` e `BitCrypto.Schnorr`)

- **ECDSA determinístico**: assina e verifica mensagens utilizando RFC 6979 (HMAC‑SHA256) para gerar *nonce* e codificação DER estrita com normalização *low‑S*.
- **Schnorr (BIP‑340)**: implementação completa de assinaturas Schnorr com normalização `x‑only` (paridade Y) e verificação constante.  Utiliza hashing etiquetado e combinações de `Core` e `Hash`.

## Tx & PSBT (`BitCrypto.Tx`, `BitCrypto.PSBT`, `BitCrypto.PSBTv2`)

Módulos dedicados à construção, serialização e assinatura de transações e PSBTs:

- **Transações**: tipos `Transaction`, `TxIn` e `TxOut`, varint, geração de `txid`/`wtxid` e implementação completa de sighash para modos Legacy, BIP‑143 (SegWit v0) e BIP‑341 (Taproot key‑path).  Suporta todas as flags (`ALL`, `NONE`, `SINGLE`, `ANYONECANPAY`).
- **PSBT v0/v2**: parsing, construção, assinatura e finalização de Partially Signed Bitcoin Transactions de acordo com BIP‑174 e BIP‑370.  Preserva pares desconhecidos, suporta witness e gera sumários *pretty* com listas de witness (`witness_items`, `witness_sizes`, `tap_control_block_depth`, `witness_preview`).
- **Tapscript & Miniscript**: geração e análise de scripts (incluindo `after`/`older`, `and`/`or`/`thresh`) para Taproot, com construção determinística de taptrees.  As CLIs `MSCLI` e `PSBTCLI` interagem com esses módulos.

## GPU (`BitCrypto.GPU`)

Implementa kernels em CUDA 13 para tarefas paralelas:

- **Multiplicação escalar em lote**: utiliza janelas wNAF e aloca cada thread para um conjunto de bits do escalar.  Aproveita *shuffle* intrinsics para compartilhar dados dentro de warps.
- **Busca de chaves**: funções `match` e `match_p2tr` para procurar chaves/endereços que correspondam a um determinado hash (HASH160 ou x‑only).  Processa milhões de chaves por segundo em GPUs modernas.
- **Integração**: os kernels são opcionalmente invocados pelas CLIs e testes; a duplicação de código é limitada à lógica necessária para extrair performance (Regra de não‑redundância).

## Tests & Bench (`BitCrypto.Tests` e `BitCrypto.Bench`)

- **Testes unitários e de propriedade**: verificam corretude de todas as rotas, com vetores canônicos (padrão Bitcoin Core), casos negativos e testes de consistência.  A suite roda tanto em modos CPU quanto GPU, garantindo equivalência.
- **Benchmarks**: medem throughput de operações individuais (hashing, escalar, assinatura, transações, parsing de PSBT) e geram relatórios em CSV e Markdown.  Auxiliam a avaliar melhorias como wNAF, unrolling de SHA‑256 ou futuros algoritmos como Pippenger.

## Integração e Futuro

Os módulos acima formam a base sobre a qual o BitCrypto continuará evoluindo.  O plano de continuidade (`CONTINUIDADE.md`) detalha trabalhos pendentes, incluindo **multi‑scalar multiplication (MSM)** usando Pippenger, **endomorfismo** e **Shamir's trick**, suporte a **MuSig2** e **FROST**, e implementação de **BIP‑322**.  Ao contribuir, siga as regras em `REGRAS.md`, mantenha a documentação sincronizada e consulte `MAINTENANCE.md` para os procedimentos de release.