# Referência de CLI — MSCLI / PSBTCLI (v2.1.1, 2025-09-07)

## MSCLI
- `--tapscript-from-ms "<expr>"` → imprime `tapscript=<hex>` e `tapleaf_hash=<hex32>`.
- `--taptree-from-ms "<expr1>; <expr2>; ..."` → imprime `taptree_root=<hex32>` (2+ folhas).
- `--ms-analyze "<expr>"` → contadores (pk/after/older/or*/thresh) e custo heurístico.

## PSBTCLI
- `--psbt2-decode|--psbt2-verify|--psbt2-pretty` — operações PSBT v2; *pretty* inclui `Warnings:` e, se houver, `final_scriptwitness`/profundidade do control block.
- `--psbt2-sign-final` — assinatura/finalização PSBT v2 (subset).
- `--sighash <ALL|NONE|SINGLE|DEFAULT>` + `--anyonecanpay` — modos de sighash (subset).
- `--tap-sighash <in_idx>` — calcula `tapsighash=<hex32>` para Taproot **script‑path** (ALL/DEFAULT + ANYONECANPAY).
- `--tap-witness --sig <hex> --cblock <hex> --wscript <hex>` — monta *witness stack* (3 itens).
- `--tap-finalize --psbt <b64> --in <idx> --sig <hex> --cblock <hex> --wscript <hex>` — injeta `final_scriptwitness` em um input.
- `--tap-finalize-multi --in-list "0,2,5" --sig-list "<...>;<...>" --cblock-list "<...>;<...>" --wscript-list "<...>;<...>"` — versão multi‑inputs.
