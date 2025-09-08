# Transações e PSBT (v2.5.0)

> **Nota:** Este documento foi originalmente escrito para a versão 1.1.0.  O módulo de transações e PSBT evoluiu significativamente desde então, passando a abranger serialização de transações Taproot, cálculo completo de `sighash` com flags **ALL/NONE/SINGLE/ANYONECANPAY**, e suporte a **PSBT v2** com preservação de pares desconhecidos e *pretty printer* de witness.  Para uma descrição atualizada das capacidades, consulte `ARQUITETURA.md` e as notas de release.

Este módulo cobre:
- **Transações** (`BitCrypto.Tx`): serialização, *varint*, *script builders* (P2PKH, P2WPKH, P2TR), *sighash* (Legacy/BIP143/BIP341 keypath), assinatura (ECDSA/Schnorr).
- **PSBT** (`BitCrypto.PSBT`): serialização **v0** e **v2** (subset usado em carteiras), conteúdo de `witness_utxo`, `sighash_type` e `partial_sigs`.

> Em consonância com as **Regras do Projeto**: sem dependências externas; compatível com **VS2022/Win11/CUDA 13**; sem *stubs*; mantendo não‑redundância; e documentação de retomada. 
