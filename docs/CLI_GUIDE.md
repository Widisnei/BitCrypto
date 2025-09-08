# Guia de CLIs — BitCrypto
(Comandos MSCLI: --tapscript-from-ms, --taptree-from-ms, --ms-analyze; PSBTCLI: decode/verify/pretty, --tap-sighash, --tap-witness, --tap-finalize, --tap-finalize-multi; BenchCLI.)


## WSCLI (Witness Summary)
- `BitCrypto.WSCLI --psbt <b64>` → imprime `witness_items=N` e `len[i]=...` (+ `tap_control_block_depth`).
