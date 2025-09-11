# RELEASE NOTES — v2.5.0 (2025-09-08)

- **EC**: `s·G` com **wNAF (w=4)** + **precompute de G** (odd 1..15).
- **SHA‑256**: unrolling moderado (8×) no compress.
- **PSBT pretty**: `WSCLI` agora imprime `witness_preview=[…]` (hex com truncamento 8+..+8) além de `witness_items`/`witness_sizes`/`tap_control_block_depth`.
- **Guard‑rails**: adicionados tokens para EC (wNAF/precompute) e preview.
- **Compatibilidade**: VS2022/Win11 x64/CUDA 13; sem dependências externas.
- **MuSig2**: funções `musig2_sign`/`musig2_verify` e suporte `--musig2-sign`/`--musig2-verify` na CLI.
- **Core**: rotinas de Montgomery reescritas sem `__int128`, garantindo compilação no Visual Studio.
