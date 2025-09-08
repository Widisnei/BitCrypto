# Processo de Release (v2.1.1, 2025-09-07)

1. **Atualize docs**: README, RELEASE_NOTES_X.Y.Z.md, COMPLETUDE, PLANEJAMENTO.
2. **Rodar guard‑rails** (raiz do projeto).
3. **Empacote** com `python tools/guardrails/package_release.py vX.Y.Z` → ZIP + MANIFEST (BitCrypto/raiz única).
4. **Valide** manifesto vs. ZIP (`check_manifest.py`), deps externas, stubs, features.
5. **Publique** a release no GitHub com artefatos e notas.
