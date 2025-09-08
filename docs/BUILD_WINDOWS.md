# BUILD — Windows 11 x64 + VS2022 + CUDA 13 (v2.1.1, 2025-09-07)

## Pré-requisitos
- **Visual Studio 2022** (C++ Desktop) e **CUDA 13** instalados.
- Padrões: C++20, *Optimization* habilitada para Release x64.

## Passos gerais
1. Abra a solução/projeto ou gere via CMake/VS:
   - Se houver `CMakeLists.txt`, use *"Open Folder"* no VS e gere a solution.
   - Caso contrário, crie **projetos Console** separados para `BitCrypto.MSCLI`, `BitCrypto.PSBTCLI` e `BitCrypto.BenchCLI` e inclua os diretórios `BitCrypto.*` respectivos.
2. Incluir **Include Directories** com `BitCrypto.*/include` e dependências internas (`BitCrypto.Hash`, `BitCrypto.Tx`, `BitCrypto.PSBTv2`, etc.).
3. Para CUDA, inclua `BitCrypto.GPU/src/*.cu` (Compute Capability compatível com sua GPU).

## Guard‑rails locais
```powershell
python tools/guardrails/check_no_external_deps.py
python tools/guardrails/check_stubs.py
python tools/guardrails/check_features.py
python tools/guardrails/check_manifest.py
```
