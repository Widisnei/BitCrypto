# CHANGELOG — BitCrypto

## [2.5.0] — wNAF + precompute(G); SHA‑256 unrolling; PSBT pretty
### Added
- EC: `s·G` com **wNAF (w=4)** + **precompute de G** (odd 1..15).
- SHA‑256: **unrolling moderado** (8 rounds/bloco) no compress.
- WSCLI: **`witness_preview=[…]`** com truncamento seguro (8+..+8).
### Changed
- Guard‑rails: tokens EC(wNAF/precompute) e `witness_preview` adicionados.

## [2.4.6] — Superset + limpeza de docs
### Added
- WSCLI com witness summary; MSCLI com `--taptree-pair-by-hash`; PSBTv2 preserva unknown K/V.
### Changed
- Limpeza de documentação e atualização de ROADMAP/CHANGELOG.
## [2.4.2] — Consolidação overlay 2.3.1
### Added
- fe256, EC Jacobiano, Schnorr BIP‑340 verify, SHA‑256/tagged hash; guard‑rails e manifesto.
## [2.3.0] — Campo + EC + Schnorr
### Added
- fe256, EC Jacobiano, Schnorr BIP‑340 verify (CLI), SHA‑256 tagged_hash.
