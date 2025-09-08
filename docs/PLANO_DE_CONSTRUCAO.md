# Plano de Construção — BitCrypto

> **Nota:** Este plano foi elaborado para as versões 0.x/1.x da biblioteca.  Com a evolução para a série 2.x, o roadmap e a descrição dos marcos foram consolidados em `ROADMAP.md` e nas notas de release (`RELEASE_NOTES_*.md`).  Este documento permanece para fins de histórico e contexto.

> Este documento consolida o **planejamento incremental** para a construção da biblioteca, garantindo retomada segura (ver também `docs/FLUXO_DE_CONSTRUCAO.md`).

## Visão Geral dos Marcos
- **0.9.0**: Assinaturas **ECDSA (RFC6979)** e **Schnorr (BIP‑340)**; DER estrito; campo **Fn** (ordem **n**) com Montgomery.
- **1.0.0**: **SHA‑512**, **HMAC‑SHA512**, **PBKDF2‑HMAC‑SHA512**; **BIP‑32/39/44** (infra), **RNG** Windows CNG.
- **1.0.1**: **Base58/Base58Check** robustos; import/export **xprv/xpub**; `ckd_pub` (não‑hardened); CLI para derivação pública.
- **1.1.0** *(este marco)*: **Transações** (P2PKH/P2WPKH/P2TR‑keypath), **Sighash** (legacy, BIP‑143, BIP‑341‑keypath) e **PSBT v0/v2** (mínimo) — com foco em **SIGHASH_ALL**; CLI mínima para construir tx / calcular *sighash* / serializar PSBT.
- **Próximos (sujeitos a priorização)**:
  - **1.1.x**: Finalização e *round‑trip* PSBT (import decode), *finalizers* de inputs (scriptSig/witness), export/import completo de assinaturas Taproot.
  - **1.2.0**: Otimizações de curva (wNAF/Pippenger), *batch verify* e aceleração opcional em **GPU (CUDA)** onde fizer sentido.
  - **1.3.0**: Transações completas (sighash variantes, SIGHASH_SINGLE/NONE/ANYONECANPAY), PSBT v2 avançado, interpretador Script mínimo para testes.
  - **1.4.0**: Hardening (passes de *const‑time*, sanitização, *fuzz leve*), documentação de *threat model*.


## Diretrizes do Projeto
- **Sem dependências externas** — apenas **VS2022/C++/CUDA** e APIs nativas (RNG via CNG).
- **Compatibilidade** garantida com **VS2022/Win11 x64/CUDA 13**.
- **Sem stubs**: cada entrega é funcional e testável; quando houver limitações de escopo, elas são documentadas e as APIs permanecem válidas.
- **Não‑redundância**: reaproveitar o que já existe; quando necessário criar variantes (ex.: `Fp` vs `Fn`), isolar bem por módulo.
- **Boas práticas** de bibliotecas de referência (apenas como **base conceitual**; sem copiar código).
- **Retomada segura** em caso de perda de contexto (documentos `docs/FLUXO_DE_CONSTRUCAO.md` e este **Plano**).


## Escopo técnico deste marco (1.1.0)
- **Serialização/Deserialização** de transações com/sem witness.
- **Scripts** utilitários: `P2PKH`, `P2WPKH`, `P2TR` (keypath).
- **Sighash**:
  - Legacy SIGHASH_ALL (pré‑SegWit).
  - SegWit v0 (BIP‑143) SIGHASH_ALL (P2WPKH).
  - Taproot (BIP‑341) **key‑path**, **SIGHASH_DEFAULT/ALL**, sem *annex* (primeira fase).
- **PSBT**:
  - **v0 (BIP‑174)**: geração mínima com `unsigned_tx`, witness UTXO e *partial_sigs*.
  - **v2 (BIP‑370)**: campos globais básicos (versão, locktime, nIns/nOuts) e metadados essenciais por input.

> **Nota de escopo**: para Taproot, esta entrega implementa **key‑path** (sem *script‑path*, sem *annex*). As APIs são estáveis para evoluir sem *breaks* quando adicionarmos os demais casos.



### ✅ 1.1.1
- **Taproot (P2TR key‑path)**: tweak, sighash e assinatura Schnorr BIP‑340 com witness mínimo (64/65B).
- **PSBT v2** (BIP‑370, subset útil p/ P2WPKH/P2TR): criação, assinatura e finalização.
- **CLI** atualizado; testes de sanidade P2TR.
