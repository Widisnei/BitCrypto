# ACEITE_QA — v2.4.2 (2025-09-08)

## Guard‑rails
```
python tools/guardrails/check_no_external_deps.py
python tools/guardrails/check_stubs.py
python tools/guardrails/check_features.py
python tools/guardrails/check_constant_time_heuristic.py
python tools/guardrails/check_manifest.py
```

## Smoke tests
1) Schnorr: `BitCrypto.SchnorrCLI --bip340-verify --pubx <px> --msg <m> --sig <r||s>` ⇒ `bip340_verify=ok`.
2) EC: `scalar_mul(G,1)` ⇒ `G`; `lift_x_even_y(Gx)` ⇒ Y par.
3) PSBT pretty: `witness_items=N` e `witness_sizes=[...]` (CompactSize).
4) MSCLI: `--taptree-pair-by-hash` ⇒ `taptree_root=<hex32>`.
5) PSBT v2: pares desconhecidos preservados (compat. Taproot extended fields).
