# BitCrypto v2.5.0

BitCrypto é uma biblioteca **sem dependências externas** (apenas C++/CUDA/VS2022) para operações criptográficas sobre a curva **secp256k1**, hashing, codificação de chaves/endereços, assinaturas, transações e PSBT.  A versão 2.5.0 consolida todas as entregas anteriores e introduz otimizações significativas (wNAF com pré‑cálculo, unrolling moderado de SHA‑256) mantendo compatibilidade com **VS2022**, **Windows 11 x64** e **CUDA 13**.

## Módulos

BitCrypto é organizado em diversos submódulos coesos:

- **Core**: tipos numéricos (`U256`), campos de curva (`Fp` e `Fn`) com redução pseudo‑Mersenne, operações de ponto em coordenadas Jacobianas, escalar com *ladder* constante e otimizações **wNAF (janela 4) com pré‑cálculo** para `s·G`, além de **MSM Pippenger** com janelas adaptativas e contexto de **precompute**, rotinas de **endomorphism** e **Shamir's trick** para decompor escalares e combinar `a·P + b·G`, bem como utilitários como `secure_memzero`.
- **Hash**: `SHA‑256`/`SHA‑512`, `RIPEMD‑160`, HMACs (`HMAC‑SHA256`/`HMAC‑SHA512`), `PBKDF2‑HMAC‑SHA512`, `HASH160` e `sha256_tagged` (BIP‑340/341).
- **Encoding**: codificadores Base58/Base58Check, Bech32/Bech32m, WIF (encode/decode), tratamento de endereços **P2PKH**, **P2WPKH** e **P2TR**, bem como `detect_address_kind` e codificação/decodificação de xprv/xpub.
- **KDF & HD**: wrapper de RNG via Windows CNG (`BCryptGenRandom`); derivação de carteiras HD conforme BIP‑32/39/44 (mnemonic → seed, CKD priv/pub, xprv/xpub).
- **Sign**: assinaturas determinísticas **ECDSA** (RFC6979, DER estrito, low‑S) e **Schnorr** (BIP‑340) com verificação completa, agregação de chaves, *nonces* e assinaturas parciais **MuSig2** usando MSM Pippenger.
- **Tx & PSBT**: serialização de transações legadas, SegWit v0 e Taproot (v1); cálculo de `txid/wtxid` e `sighash` (legacy/BIP‑143/BIP‑341) com suportes **ALL**, **NONE**, **SINGLE** e **ANYONECANPAY**; criação, parsing, assinatura e finalização de **PSBT v0/v2**, preservando pares desconhecidos e gerando saída *pretty* com sumário de witness (`witness_items/sizes/preview`).
- **Miniscript & CLI**: análise e geração de fragmentos Miniscript (timelocks, `and`/`or`/`thresh`) com hints `after/older`; reconstrução de taptrees via `--taptree-pair-by-hash`; CLIs para geração de chaves, assinatura/validação ECDSA/Schnorr, operações de HD wallet, construção e assinatura de transações/PSBT, e resumos de witness.
- **GPU**: aceleração via CUDA (13) para **multiplicação escalar em lote** e busca paralela de **HASH160**/P2TR (`x‑only(Q)`), com suporte a janelas wNAF e *block size* configurável.
- **Tests & Bench**: conjunto completo de testes (vetores canônicos, testes negativos e de propriedade) cobrindo todas as rotas críticas; benchmarks de throughput (CPU/GPU) com exportação para CSV/Markdown (consulte `docs/BENCHMARKS.md`).

## Build (VS2022 + CUDA 13)
1. Abra a pasta no VS2022 (CMake + Presets).
2. Escolha `windows-release` ou `windows-relwithdebinfo`.
3. Compile os alvos desejados.

## CLI — exemplos
```bash
BitCrypto.CLI --priv 01 --address      # P2PKH
BitCrypto.CLI --priv 01 --bech32       # P2WPKH
BitCrypto.CLI --priv 01 --taproot      # P2TR
BitCrypto.CLI --batch privs.txt --gpu --match tb1q... --both   # HASH160 (GPU)
BitCrypto.CLI --batch privs.txt --gpu --match bc1p...          # P2TR (GPU)
```


## Novidades 0.9.0
- **Assinaturas**: **ECDSA** (RFC6979, **low‑S**, **DER** estrito) e **Schnorr** (**BIP‑340**).
- **Hash**: **HMAC‑SHA256** (para RFC6979).
- **Core**: `Fp::sqrt` e `parse_pubkey` (comprimida/nao) com validação de curva.
- **CLI**: `--sign-ecdsa`, `--verify-ecdsa`, `--sign-schnorr`, `--verify-schnorr`, `--msghex`, `--sig`, `--pub`.
- **Tests**: round‑trips de ECDSA/Schnorr e negativos de DER.


## Novidades 1.0.0
- **RNG (Windows CNG)**: `BCryptGenRandom` wrapper (nativo do SO; sem deps externas).
- **SHA-512 / HMAC-SHA512** e **PBKDF2-HMAC-SHA512** (para HD Wallets).
- **BIP-32**: master a partir da seed, CKD priv/pub (hardened e não‑hardened), `xprv/xpub` main/test, Base58Check.
- **BIP-39**: derivação de **seed** a partir de *mnemonic* + *passphrase* (2048 iterações, 64B).
- **CLI**: `--bip39-seed`, `--bip39-generate` (com `--wordlist`), `--bip32-master`, `--bip32-derive`, `--xpub-from-xprv`.
- **Tests**: propriedades BIP‑32 e checagem básica de BIP‑39 seed.


## Novidades 1.0.1
- **Base58/Base58Check** reescritos (sem placeholders) e robustos.
- **BIP‑32 import/export**: `from_base58_xprv/xpub` e `to_base58_xprv/xpub`.
- **CLI**: `--xpub-from-xprv`, `--derive-pub --xpub <base58> "m/.../..."` e `--derive` com `--xprv <base58>`.
- **Testes**: *round‑trip* xprv/xpub, e **consistência** `neuter(ckd_priv) == ckd_pub` para não‑hardened.


## Novidades 1.1.0
- **Transações**: Legacy/SegWit v0 (`txid/wtxid`), varint.
- **SIGHASH**: Legacy e **BIP‑143 (P2WPKH, SIGHASH_ALL)**.
- **PSBT v0** (mínimo P2WPKH): assinar e finalizar.
- **Testes**: fluxo end‑to‑end P2WPKH.


## Novidades 1.1.1
- **Taproot (P2TR)**: *key‑path* com **Schnorr BIP‑340** + **SIGHASH (BIP‑341)**.
- **PSBT v0**: suporte a inputs **P2TR** (witness_utxo) em `sign_psbt()` e `finalize_psbt()`.
- **PSBT v2 (BIP‑370)**: **Creator/Constructor** (serializer) para inputs/outputs (chaves mínimas), via `BitCrypto.PSBTv2`.
- **CLI**: `--taproot-from-priv` (gera xonly + scriptPubKey P2TR), `--psbt2-create`.


## Novidades 1.1.2
- **Bech32/Bech32m** (endereços SegWit v0/v1): encode/decode e helpers para `scriptPubKey` (v0/v1).
- **PSBT v2 (BIP‑370)**: parse e **assinatura/extract** via *bridge* para PSBT v0 (suporte a **witness_utxo** em P2WPKH/P2TR).
- **CLI**: `--psbt2-sign`, `--psbt2-final` e suporte a endereço bech32/bech32m em `--tx-out`.

## Novidades 1.4.1
- PSBTCLI: --sighash ALL|NONE|SINGLE|DEFAULT e --anyonecanpay.

## Novidades 1.4.0
- Miniscript: after/older e and().
- MSCLI: wpkh/p2shwpkh.
- PSBTv2: P2SH-P2WPKH.


## Novidades 1.5.0
- **PSBTCLI**: `--infer-timelocks` — detecta `after(n)` (*CLTV*) e `older(n)` (*CSV*) nos `witness_script` e ajusta **nLockTime** e **nSequence** automaticamente antes de assinar.
- **MSCLI**: `--analyze-ms "<expr>"` — imprime `wscript`, `wsh`, `address` e **hints de timelock** (`after=n`/`older=n`).
- **Qualidade**: mantém compatibilidade com as features anteriores (P2SH‑P2WPKH, P2SH‑P2WSH, multisig, etc.).

## Novidades 2.x

A partir da série 2.x a biblioteca expandiu-se para além de assinaturas e transações básicas, incluindo campo `Fe`, melhorias em curvas, otimizações e ferramentas de depuração:

- **2.3.0** – Implementação completa do campo primo secp256k1 (`Fe`) com redução pseudo‑Mersenne e operações `add/sub/mul/sqr/inv/sqrt`; adição de coordenadas Jacobianas e verificação **Schnorr** em `SchnorrCLI`.
- **2.4.2** – Consolidação do overlay 2.3.1 (Fe/EC/Schnorr/Hash) e atualização de tokens de guard‑rails para PSBT/Miniscript.
- **2.4.6** – **WSCLI** ganhou sumário de witness (`witness_items`, `witness_sizes`, `tap_control_block_depth`); **MSCLI** adicionou `--taptree-pair-by-hash` para reconstrução determinística de Taproot; **PSBT v2** passou a preservar pares *unknown K/V*.
- **2.5.0** – Otimização da multiplicação `s·G` com **wNAF (janela 4)** e pré‑cálculo de G; unrolling moderado de `SHA‑256` (8×); expansão de **PSBT pretty** com `witness_preview=[…]`; tokens de guard‑rails adicionais para EC e witness preview; agregação de chaves, *nonces* e assinaturas parciais **MuSig2**.

## Documentação

Os documentos principais do projeto encontram‑se na raiz do repositório:

- **CHANGELOG.md** — histórico de versões.
- **ROADMAP.md** — planejamento de marcos futuros.
- **AGENTS.md** — diretrizes de continuidade e playbooks.
- **MAINTENANCE.md** — procedimentos de manutenção e release.
- **CONTINUIDADE.md** — plano de continuidade e guias para novas contribuições.
- **MAINTAINERS.md** — lista dos mantenedores e responsabilidades de governança.
- **SECURITY.md** — modelo de ameaças e medidas de segurança.
- **docs/** — notas de release (`RELEASE_NOTES_*`), aceites de QA (`ACEITE_QA_*`), guias de CLI/benchmarks e arquivos auxiliares (consulte `docs/README_DOCS.md`).
