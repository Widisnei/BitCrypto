# ACEITE_QA — v2.5.0 (2025-09-08)

## Guard‑rails
```
python tools/guardrails/check_no_external_deps.py
python tools/guardrails/check_stubs.py
python tools/guardrails/check_features.py
python tools/guardrails/check_constant_time_heuristic.py
python tools/guardrails/check_manifest.py
```

## Smoke tests
1) EC: validar `scalar_mul_base_wnaf` com casos aleatórios vs ladder constante.
2) SHA‑256: vetores conhecidos (RFC 6234).
3) WSCLI: `witness_items`, `witness_sizes`, `witness_preview` e `tap_control_block_depth`.
4) Schnorr: `--bip340-verify`.
