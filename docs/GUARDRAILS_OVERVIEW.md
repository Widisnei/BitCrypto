# GUARD-RAILS — visão e uso (v2.1.1, 2025-09-07)

Scripts em `tools/guardrails/`:
- `check_no_external_deps.py`: bloqueia includes/buscas por libs externas.
- `check_stubs.py`: reprova TODO/FIXME/stubs no **código** (docs ignoradas).
- `check_features.py`: cobra *tokens/âncoras* de features esperadas.
- `check_manifest.py`: confere ZIP vs. manifesto (tolera auto‑referência).
- `package_release.py`: empacota com **raiz única** e **sem resíduos**.

## Pipeline recomendado (CI/GitHub Actions)
1) Rodar **guard‑rails**.  
2) Empacotar: `python tools/guardrails/package_release.py vX.Y.Z`.  
3) Anexar ZIP + MANIFEST à release, com notas de versão.
