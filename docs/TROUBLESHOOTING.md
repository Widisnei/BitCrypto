# TROUBLESHOOTING — problemas comuns (v2.1.1, 2025-09-07)

- **Estrutura duplicada `BitCrypto/BitCrypto/...`**: reempacote com `package_release.py` (raiz única garantida).
- **Falha em `check_features.py`**: faltam *tokens* — implemente/ligue a feature ou ajuste o script.
- **`check_no_external_deps.py` reprovando**: remova qualquer include externo ou `find_package(...)` residual.
- **`psbt2-verify` reprovando**: veja *Warnings* e mensagens de incoerência CLTV/CSV no pretty; verifique `nLockTime`/`nSequence`.
- **`--tap-sighash`**: requer UTXO por input (`witness_utxo` ou `non_witness_utxo+vout` coerentes).
- **`--tap-finalize(-multi)`**: verifique hex de `--sig/--cblock/--wscript`; *control block* deve ter tamanho 33+32*N.
