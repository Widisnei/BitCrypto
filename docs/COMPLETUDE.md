# COMPLETUDE — Histórico de Marcos (v2.5.0)

Este documento resume os principais marcos já alcançados pelo BitCrypto e serve como checklist de completude.  Ele consolida as funcionalidades adicionadas ao longo do tempo e ajuda a contextualizar as notas de release.  Para mais detalhes, consulte `CHANGELOG.md` e os arquivos `RELEASE_NOTES_*.md`.

## v0.9.0 – v1.6.x (histórico)

Durante as séries 0.x e 1.x foram introduzidas as assinaturas determinísticas **ECDSA** (RFC6979) e **Schnorr** (BIP‑340), funções de hash `SHA‑512`/`HMAC‑SHA512`/`PBKDF2‑HMAC‑SHA512`, suporte a carteiras HD (**BIP‑32/39/44**), codificadores robustos Base58/Base58Check/Bech32/Bech32m, construção e assinatura de transações (P2PKH/P2WPKH/P2TR‑keypath), PSBT v0/v2 mínimos, ferramentas de CLI para assinatura, derivação e construção de transações, além de melhorias de robustez (low‑S, DER estrito, randomização de nonce via auxrand), inferência de timelocks em Miniscript e suporte a flags SIGHASH e ANYONECANPAY.

## v2.3.0

- Introdução do campo primo secp256k1 (`Fe`) com redução pseudo‑Mersenne e operações completas (`add/sub/mul/sqr/inv/sqrt`).
- Adição de coordenadas Jacobianas e rotas de multiplicação escalar (`scalar_mul`) em `BitCrypto.Core`.
- Suporte a verificação de assinaturas **Schnorr BIP‑340** com `SchnorrCLI`, incluindo `sha256_tagged` e checagens x‑only.
- Guard‑rails atualizados para EC/Fe/Schnorr e heurísticas de tempo constante.

## v2.4.2

- Consolidação do overlay 2.3.1, incorporando melhorias de **Fe**, **EC**, **Schnorr** e hashing.
- Atualização de tokens de guard‑rails para **PSBT**, **Miniscript** e **Schnorr**.

## v2.4.6

- **WSCLI** passou a imprimir sumários de witness (`witness_items`, `witness_sizes`, `tap_control_block_depth`).
- **MSCLI** ganhou a opção `--taptree-pair-by-hash` para reconstrução determinística de taptrees via hash.
- **PSBT v2** passou a preservar pares **unknown K/V** (globais/inputs/outputs), garantindo compatibilidade com extensões futuras do protocolo.
- Foi realizada uma limpeza geral na documentação e atualizados **ROADMAP/CHANGELOG**.

## v2.5.0

- Otimização da multiplicação escalar `s·G` com **wNAF** (janela 4) e **pré‑cálculo de G** (odd 1..15), aumentando a velocidade de geração de pontos.
- Unrolling moderado (8 rounds/bloco) na implementação de `SHA‑256`, melhorando o throughput sem sacrificar portabilidade.
- Expansão do *pretty‑printer* de PSBT (**WSCLI**) com `witness_preview=[…]`, exibindo os primeiros e últimos 8 bytes de cada elemento da witness de forma segura.
- Guard‑rails reforçados com tokens adicionais para EC (wNAF/precompute) e preview de witness; manifesto e integridade validados.
- Compatibilidade confirmada com Visual Studio 2022, Windows 11 x64 e CUDA 13, mantendo **zero dependências externas**.
- Introdução da multiplicação multi‑escalar **MSM Pippenger** com janelas adaptativas, suporte a **wNAF** e contexto opcional de **precompute**.

## Notas adicionais

- Os arquivos `ACEITE_QA_*.md` detalham os testes de fumaça e procedimentos de validação para cada release.
- As notas de release (`RELEASE_NOTES_*.md`) fornecem uma descrição concisa das mudanças e melhorias de cada versão.
- O **ROADMAP** em `ROADMAP.md` lista os marcos futuros planejados, enquanto o **CHANGELOG** fornece um histórico resumido das versões.