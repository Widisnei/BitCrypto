# Plano de Implementação — BitCrypto (foco em robustez & completude)

> **Nota:** Este plano reflete o roadmap detalhado das versões 0.x/1.x.  A partir da versão 2.x as fases de implementação foram concluídas e os novos marcos são documentados em `ROADMAP.md` e `RELEASE_NOTES_*.md`.  Este documento permanece aqui como registro histórico das decisões de projeto e critérios de aceitação.

**Objetivo**: evoluir os módulos críticos da biblioteca até um nível de robustez e completude **análogo** às bibliotecas de referência (secp256k1, libbitcoin‑system, openssl::bn, Kangaroo), mantendo **zero dependências externas**, compatibilidade com **VS2022/Win11 x64/CUDA 13** e seguindo as regras do projeto.

---

## 1) Definições globais (Definition of Done)

- **Sem dependências externas** (apenas C++/CUDA/VS2022).
- **Compatibilidade**: compila e executa em Windows 11 x64 + VS2022 + CUDA 13.
- **Completo**: nenhuma função “stub”/placeholder; entradas, saídas e erros bem definidos.
- **Não‑redundância**: duplicidades apenas quando **CPU vs GPU** justificar.
- **Constante no segredo**: operações que envolvem material secreto **sem ramos**/acessos dependentes de segredo (quando aplicável).
- **Testes**: unitários + vetores canônicos + negativos + *property tests*; cobertura dos caminhos críticos.
- **Benchmarks**: `BitCrypto.Bench` atualizado para as novas rotas; export CSV/Markdown.
- **Documentação**: README, ARQUITETURA, FLUXO_DE_CONSTRUCAO e este plano sempre atualizados.
- **Zeroization**: buffers sensíveis apagados em todas as saídas de rotas que manipulam segredos.

---

## 2) Mapa de Módulos e Marcos

### M0 — Fundamentos e Qualidade (base contínua)
- **Core/U256/Fp/EC**: const‑time helpers (cmov/cswap), auditoria de *carry/borrow* e reduções.
- **Hash**: SHA‑256/RIPEMD‑160 estáveis; adicionar **SHA‑512**.
- **Infra**: `secure_memzero`, `Result<T>` simples (código de erro + enum), logging mínimo (nivelado) sem dependências.
- **Build**: *presets* CMake, LTO/IPO opcional, *warnings* `/W4`.

**Critérios**: testes de regressão; *property tests* em aritmética; `BitCrypto.Tests` sem falhas; *bench* básico roda e exporta CSV/MD.

---

### M1 — Assinaturas: **ECDSA** (RFC6979) e **Schnorr** (BIP‑340)
**Entregas**
1. **SHA‑512** + **HMAC‑SHA256/HMAC‑SHA512** (headers‑only) com vetores canônicos (RFC 4231).
2. **Deterministic ECDSA (RFC 6979)**: função `ecdsa_sign(k,msg)` com **low‑S** e **DER** *encode/decode*.
3. **ECDSA verify**: checagem completa e resistente a malformações.
4. **Schnorr BIP‑340**: *nonce* com *auxrand*, `sha256_tagged`, *lift_x* implícito pela nossa `x‑only` + normalização Y par.
5. **CLI**: `--sign-ecdsa`, `--verify-ecdsa`, `--sign-schnorr`, `--verify-schnorr` (hex in/out).

**Testes**
- Vetores públicos (ECDSA/Schnorr), casos de *malformed* DER, *edge cases* (k=1, n−1), rejeição de **high‑S**.
- *Property*: `verify(sign(m,k), m) == ok` para amostras aleatórias (com PRNG determinístico de teste).

**Bench**
- Throughput de `sign`/`verify` (CPU).

---

### M2 — **HD Wallet (BIP‑32)** e utilidades
**Entregas**
1. **SHA‑512** + **HMAC‑SHA512** reutilizados; `CKDpriv`/`CKDpub` (hardened/normal).
2. **Ext keys** (xprv/xpub) Base58Check: *encode/decode* + checks (versões main/test).
3. CLI: `--bip32-from-seed`, `--bip32-derive m/…` (hex/serialized), export xprv/xpub.

**Testes**
- Vetores públicos do BIP‑32 e casos negativos (índices fora de faixa, *versions* incorretas).

**Bench**
- Derivação em lote (CPU), opcional *threading* via C++ `std::thread`.

---

### M3 — **Transações, PSBT e Sighash**
**Entregas**
1. **Serialização TX** (*legacy*, segwit v0, taproot v1): estrutura, *varint*, *scripts* utilitários.
2. **Sighash**: legacy (SIGHASH_ALL/NONE/SINGLE + ANYONECANPAY), **BIP‑143** (v0), **BIP‑341** (keypath v1).
3. **Assinatura**: P2PKH, P2WPKH, P2TR (*keypath*); montagem de `scriptSig`/`witness`.
4. **PSBT v0** (BIP‑174): *parse/build* (base64), *combine*, *finalize* para P2PKH/P2WPKH/P2TR‑keypath.
5. CLI: `--tx-new`, `--tx-sign`, `--psbt-create`, `--psbt-sign`, `--psbt-finalize`.

**Testes**
- Vetores canônicos para *sighash* (v0/v1), PSBT de referência, casos negativos (campos duplicados, *unknowns* preservados).

**Bench**
- *Sighash* em lote (CPU).

---

### M4 — **GPU** (aceleração prática e segura)
**Entregas**
1. *Match* **HASH160** e **P2TR** já disponíveis → **otimização** (layout SoA, *batch*, *launch_bounds*).
2. **Scalar_mul** com *precomputation* de **G** (p‑window) opcional e *occupancy tuning*.
3. (Opcional) **ECDSA verify** em GPU (lote) — foco em verificação.

**Testes**
- *Golden tests* CPU vs GPU (mesmo *seed*) e validação bit‑a‑bit; *stress* com lotes grandes.

**Bench**
- Throughput por *block size* parametrizável; export CSV/MD.

---

### M5 — **Fuzz/Robustez/Segurança**
- *Fuzz leve* (geração pseudo‑aleatória determinística) em encoders e parsers (Base58/Bech32/DER/PSBT).
- **Consistência** de erros (enums/documentação).
- **Zeroization** e *lifetime* de segredos auditados (inclui CLI).

---

## 3) Backlog de Tarefas (checklist)

- [ ] SHA‑512 (integração em `BitCrypto.Hash`).
- [ ] HMAC‑SHA256/HMAC‑SHA512 (headers‑only).
- [ ] ASN.1 DER (ECDSA) *encode/decode* robusto.
- [ ] ECDSA (RFC6979) sign/verify + low‑S enforcement.
- [ ] Schnorr BIP‑340 sign/verify (keypath), com `sha256_tagged` e `x‑only`.
- [ ] CLI: rotas de assinatura/verificação.
- [ ] BIP‑32 (CKDpriv/CKDpub) + xprv/xpub Base58Check.
- [ ] CLI: `--bip32-from-seed`, `--bip32-derive`.
- [ ] TX core (serialização + scripts utilitários).
- [ ] Sighash legacy, BIP‑143 (v0), BIP‑341 (v1 keypath).
- [ ] PSBT v0: parse/build/combine/finalize (+Base64).
- [ ] CLI: `--tx-*`, `--psbt-*`.
- [ ] GPU: SoA/precomp/tuning + *golden tests* CPU↔GPU.
- [ ] Fuzz leve e casos negativos adicionais (DER/PSBT/Bech32).

---

## 4) Critérios de Aceitação por Entrega

Cada item acima deve passar por:
1. **Testes determinísticos** (vetores conhecidos + negativos),
2. **Property tests** (onde aplicável),
3. **Bench** atualizado com export CSV/MD (quando faz sentido medir),
4. **Documentação** atualizada (README + ARQUITETURA + FLUXO + BENCHMARKS),
5. **Revisão de segurança** (const‑time, *zeroization*, validação de entradas).

---

## 5) Diretrizes de Implementação

- **Const‑time / side‑channels**: evitar ramos/índices dependentes de segredo; usar `cswap/cmov`.
- **Não‑redundância**: preferir uma única implementação por operação; duplicar apenas para **CPU/GPU** quando necessário.
- **Compatibilidade**: evitar extensões não‑portáveis; onde necessário, *ifdefs* bem localizados.
- **Erros**: centralizar *enums* e mensagens curtas; retornar `Result<T>`.
- **Comentários**: técnicos, em PT‑BR, citando *racional* e invariantes.
- **Sem dependências externas**: somente STL/CUDA/WinAPI (ex.: `BCryptGenRandom` na coleta de entropia).

---

## 6) Métricas de Qualidade (por release)

- Testes críticos **100%** dos caminhos; sem *flaky*.
- `BitCrypto.Tests` e `BitCrypto.Bench` compilam e executam sem falhas em VS2022/Win11 x64/CUDA 13.
- `README.md` e `docs/` atualizados; `PLANO_DE_IMPLEMENTACAO.md` sincronizado.
- *Warnings*: zero *warnings* em `/W4` (MSVC).

---

## 7) Observações finais

- Onde a robustez exigir, incluiremos vetores canônicos **embutidos** nos testes (sem baixar/depender de nada).
- Técnicas serão inspiradas pelas referências (secp256k1/libbitcoin/openssl::bn/Kangaroo), porém **sem copiar** código.


## 1.1.0 — Transações, Sighash e PSBT
**Objetivo:** Implementar construção/assinatura de transações (Legacy/P2WPKH/Taproot keypath), *sighash* completo (ALL/NONE/SINGLE + ANYONECANPAY) e PSBT v0/v2 (subset prático), além de fluxos no CLI.

### Escopo
- `BitCrypto.Tx`: tipos `Transaction/TxIn/TxOut`, *varint*, *script builders*, *serialize*, *sighash* (Legacy/BIP143/BIP341 keypath), *sign* (ECDSA/Schnorr).
- `BitCrypto.PSBT`: encoder/decoder mínimo para casos comuns (witness_utxo + sighash + partial_sigs).
- CLI: `--tx-build` (1-in / 1–2-out), saída raw tx hex ou PSBT (base64).

### Critérios de aceite
- Assinar/verificar transações P2PKH/P2WPKH/P2TR(keypath) com SIGHASH_ALL; flags NONE/SINGLE/ANYONECANPAY suportadas no *sighash*.
- PSBT v0/v2 gerado com `witness_utxo` correto e `sighash_type` quando diferente do padrão.

### Não metas deste marco
- Taproot *script path* (árvore), annex, malleability rules especiais, *finalizer* completo de PSBT. Esses itens entram no backlog.
