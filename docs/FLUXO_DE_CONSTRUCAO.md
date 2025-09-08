# FLUXO_DE_CONSTRUCAO

> **Nota:** Este arquivo documenta o fluxo de construção das versões 0.x/1.x do BitCrypto.  A partir da série 2.x o processo de construção foi simplificado e consolidado; consulte os arquivos `README.md` e `docs/RELEASE_NOTES_*.md` para orientações atualizadas.  Mantemos este histórico para fins de referência e retomada.
## 0.1.0 → 0.7.0
(ver histórico anterior)

## 0.8.0
- Benchmarks com export **CSV/Markdown** (`BitCrypto.Bench --csv/--md`).
- CMake: **BITCRYPTO_ENABLE_LTO** para IPO/LTO (Release/RelWithDebInfo).
- CUDA: `BITCRYPTO_CUDA_BLOCK_SIZE` + `__launch_bounds__`.
- Tests extras: HRP extremos, Base58 com zeros, coerência Bech32/Bech32m.
- Docs: `docs/BENCHMARKS.md`.


## 0.9.0
- ECDSA (RFC6979, DER estrito, low-S) e Schnorr (BIP-340).
- HMAC-SHA256 (RFC6979).
- sqrt(Fp) e parse_pubkey (comprimida/não), validação de curva.
- CLI: assinaturas e verificação.
- Tests: positivos/negativos de ECDSA/Schnorr.


## 1.0.0
- **RNG via Windows CNG** (BCryptGenRandom).
- **SHA‑512/HMAC‑SHA512** e **PBKDF2‑HMAC‑SHA512**.
- **BIP‑32** (xprv/xpub, CKD), **BIP‑39** (seed).
- CLI ampliado e **tests** de propriedades.


## 1.0.1
- Substituir **Base58/Base58Check** por versões completas (sem placeholders).
- Adicionar **import/export** BIP‑32 (xprv/xpub) e derivação pública a partir de **xpub**.
- Atualizar CLI e testes de consistência pública/privada.


## 1.1.1
- **Taproot**: implementação de `tagged_hash`, tweak de chave e `sighash` conforme **BIP‑341**; assinatura **BIP‑340**.
- **PSBT v0**: extensão para P2TR via `witness_utxo`.
- **PSBT v2**: módulo `BitCrypto.PSBTv2` para criação/serialização (Creator/Constructor). `sign/extract` do v2 serão adicionados em 1.1.2.


## 1.1.2
- **Encoding**: Bech32/Bech32m (BIP‑173/350) e integração no CLI (endereços → scriptPubKey).
- **PSBTv2**: parser e ponte para **PSBT v0** para assinar e extrair transação final (P2WPKH/P2TR com `witness_utxo`).
- **Testes**: PSBTv2 P2WPKH e P2TR end‑to‑end.


## 1.5.0
- Inferência de **timelocks** (CLTV/CSV) no **PSBTCLI** para ajustar `locktime/sequence` ao assinar.
- **MSCLI**: análise de miniscript (`--analyze-ms`) apontando `after/older` e wsh/address resultantes.
