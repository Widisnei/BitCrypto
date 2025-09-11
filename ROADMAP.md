# ROADMAP — BitCrypto (atualizado em 2025-09-08)

## Estado atual (2.5.0)
- **EC**: wNAF(w=4)+precompute de G para `s·G`; ladder constante permanece para `s·P` geral.
- **Hash**: SHA‑256 com unrolling moderado (8×) no compress.
- **PSBT pretty (WSCLI)**: witness_items/sizes/preview + tap_control_block_depth.
- **Guard‑rails**: tokens EC/WSCLI reforçados; manifesto e integridade válidos.

## Próximos marcos
### 2.5.1 — BIP-322 e MuSig2
- Suporte a assinatura e verificação de mensagens genéricas (BIP-322) com comandos de CLI.
- Funções `musig2_sign`/`musig2_verify` para combinar e validar assinaturas agregadas MuSig2 e opções `--musig2-sign`/`--musig2-verify` na CLI.

### 2.6.0 — Miniscript/Taproot
- Fragmentos adicionais de Miniscript (timelocks, and/or/thresh) + validações estruturais.
- Taproot: control block; verificação de TapLeaf/Root no WSCLI/MSCLI.

### 3.0.0 — GPU (opcional)
- Kernels EC e *Kangaroo* mantendo Regra 3 (duplicação apenas CPU/GPU).

## Resumo dos próximos marcos
- **2.5.1**: BIP-322 e comandos MuSig2.
- **2.6.0**: Miniscript avançado (timelocks, and/or/thresh), Taproot control block e validações.
- **3.0.0**: módulo GPU (EC kernels) preservando Regra 3.