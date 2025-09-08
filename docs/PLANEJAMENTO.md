# Planejamento

> **Nota:** Este planejamento corresponde às versões 1.x do BitCrypto.  Com a chegada da série 2.x, os marcos e tarefas passaram a ser documentados no `ROADMAP.md` na raiz do repositório e nas notas de release (`RELEASE_NOTES_*.md`).  As tarefas listadas a seguir foram concluídas e mantêm‑se aqui para fins de referência histórica.


### ✅ 1.1.1
- **P2TR key‑path** (BIP‑340/341), *witness* 1‑elemento.
- **PSBT v0** com P2TR (witness_utxo).
- **PSBT v2** (BIP‑370) — **subset Creator/Constructor**: serialização global/input/output mínima (tx_version, counts, prevout, index, sequence, amount, script). *Assinatura/extraction em v2 ficam para versão subsequente (1.1.2), mantendo v0 para assinatura.*


### ✅ 1.1.2
- **PSBTv2**: parse + sign/extract (via bridge v0) p/ P2WPKH/P2TR (`witness_utxo`), mantendo compatibilidade e simples manutenção.
- **Bech32/Bech32m** no módulo Encoding, com suporte no CLI.


### ✅ 1.5.0
- PSBTCLI: `--infer-timelocks` (CLTV/CSV).
- MSCLI: `--analyze-ms`.

## Próximo marco — 1.7.0
- Benchmarks CUDA, micro‑otimizações de hashing, e casos negativos adicionais.
