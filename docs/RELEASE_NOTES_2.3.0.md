# RELEASE NOTES — v2.3.0 (2025-09-08)

- **Field secp256k1 (Fe)** — implementação completa com redução **pseudo‑Mersenne** (p = 2^256 − 2^32 − 977); `add/sub/mul/sqr`, `inv` via exp., `sqrt` p≡3 (mod 4).
- **EC Jacobian (a=0)** — `pj_double`, `pj_add_mixed`, `scalar_mul` (double‑then‑add) e conversões `affine⟷jacobian`.
- **BIP‑340 (Schnorr Verify)** — `SHA‑256` com **tagged hash** e verificação *x‑only* (**even Y**), `R = s·G − e·P`, checagens `r < p` e `s < n`.
- **SchnorrCLI** — `--bip340-verify --pubx <hex32> --msg <hex32> --sig <hex64>` → imprime `bip340_verify=ok|fail`.
- **Guard‑rails** — tokens para `SchnorrCLI` e módulos **EC/Fe**; mantém `constant-time heuristic` habilitado.

> Mantidas as **Regras do Projeto**: nenhuma dependência externa; VS2022/Win11 x64/CUDA 13; implementações completas e pacote íntegro.
