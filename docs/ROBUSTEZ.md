# ROBUSTEZ E SEGURANÇA

Este projeto aplica endurecimento nas rotinas críticas:

- **Tempo constante (CPU/GPU)**: comparação de `hash160` em CPU (`utils/safe.h`) e em GPU (diferença acumulada sem *early exit*).
- **Validação de chaves privadas**: rejeita `k=0` e `k>=n` (secp256k1).
- **Decoders estritos**: Base58/Check, Bech32/Bech32m, P2WPKH/P2TR e **WIF decode** com checagens de tamanho, versão/rede e *flags*.
- **Build seguro**: `/W4 /permissive- /EHsc` no MSVC; `CMakePresets.json` para builds reproduzíveis.
- **Limpeza de memória**: utilitário *best-effort* `secure_wipe`.

Consulte também `docs/FLUXO_DE_CONSTRUCAO.md` para retomar o projeto com segurança.
