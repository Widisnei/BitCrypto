# SECURITY MODEL — princípios e limites (v2.1.1, 2025-09-07)

- **Sem dependências externas**: qualquer `#include <openssl/...>`, `<secp256k1/...>`, `<boost/...>` etc. é bloqueado por guard‑rails.
- **Compatibilidade**: VS2022/Windows 11 x64/CUDA 13 como alvo de compilação e execução.
- **Códigos completos**: sem stubs/placeholder; documentação e comentários em português.
- **Execução de script**: o verificador realiza **checagens de política** (consistência CLTV/CSV) e **não** executa script completo.
- **Taproot (BIP341/342)**: suportes utilitários; assinaturas BIP‑340 fora de escopo por enquanto (pode entrar como opcional futuro).
