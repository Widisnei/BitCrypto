# Contribuindo

Obrigado por contribuir! Siga estas diretrizes:

1. **Ambiente**: Windows 11 x64, Visual Studio 2022 e CMake; utilize as *presets* fornecidas para gerar *builds* Release/RelWithDebInfo.
2. **Sem dependências externas** — utilize apenas VS/C++/CUDA/Windows, de acordo com as **Regras** do projeto.
3. **Sem stubs/placeholders** — todas as funcionalidades devem ser implementadas completamente e documentadas em português.
4. **Não‑redundância** — evite duplicação; reutilize as implementações existentes.  Duplicação entre CPU e GPU é aceitável apenas quando há ganho de desempenho justificado.
5. **Estilo** — siga práticas de C++ moderno: const‑correctness, RAII, verificação de limites e tratamento de erros com `Result<T>`.
6. **Segurança** — implemente rotinas sensíveis em tempo constante; valide entradas de forma rigorosa e evite comportamento indefinido.
7. **Guard‑rails e testes** — execute todos os scripts de guard‑rails (`tools/guardrails/*.py`) e os testes (`BitCrypto.Tests`) antes de abrir um Pull Request.  Adicione vetores de teste e benchmarks correspondentes às novas funcionalidades.
8. **Documentação** — atualize `README.md`, `docs/ARQUITETURA.md`, `docs/COMPLETUDE.md`, `MAINTENANCE.md` e `CONTINUIDADE.md` ao introduzir mudanças.  Acrescente uma nova entrada ao `CHANGELOG.md` e crie notas de release em `docs/` conforme necessário.
9. **Tokens e Manifesto** — inclua tokens de guard‑rails para novos recursos e atualize o manifesto (`MANIFEST_vX.Y.Z.txt`) por meio do script de empacotamento.
10. **Commits/PRs** — escreva mensagens claras e descritivas, referencie issues relacionadas, forneça changelog e documentação.  Certifique‑se de que os builds de CI passem antes da revisão.

