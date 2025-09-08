# ACEITE_QA — v2.4.6 (2025-09-08)

## Guard‑rails
```
python tools/guardrails/check_no_external_deps.py
python tools/guardrails/check_stubs.py
python tools/guardrails/check_features.py
python tools/guardrails/check_constant_time_heuristic.py
python tools/guardrails/check_manifest.py
```

## Smoke tests
1) **WSCLI witness**: `BitCrypto.WSCLI --psbt <psbt_v2_base64>` ⇒ `witness_items=`, `witness_sizes=[…]` e `tap_control_block_depth=` (quando aplicável).
2) **MSCLI pair-by-hash**: `BitCrypto.MSCLI --taptree-pair-by-hash "<ms1>; <ms2>; ..."` ⇒ `taptree_root=<hex32>`.
3) **PSBTv2 round‑trip**: **unknown K/V** preservados após decode→encode.
4) **Schnorr**: `BitCrypto.SchnorrCLI --bip340-verify ...` ⇒ `bip340_verify=ok`.
