# Manutenção do Projeto BitCrypto

Este documento descreve as responsabilidades e procedimentos que garantem que o BitCrypto permaneça robusto, seguro e livre de regressões ao longo do tempo.  Todos os mantenedores e contribuidores devem seguir estas diretrizes antes de integrar novas funcionalidades ou publicar uma release.

## Ambiente e Dependências

- **Compatibilidade**: mantenha o suporte a Visual Studio 2022, Windows 11 x64 e CUDA 13.  Teste também nas configurações de *Release* e *RelWithDebInfo*.
- **Zero dependências externas**: não adicione bibliotecas de terceiros.  Utilize apenas C++ padrão, APIs nativas do Windows e CUDA.  Verifique se qualquer nova biblioteca introduzida pelo compilador (e.g., C++ standard library) está permitida.
- **Compilação limpa**: o projeto deve compilar sem *warnings* em `/W4` e sem erros de sanitizadores.  Utilize as *presets* CMake fornecidas e garanta que `BitCrypto.Tests` e `BitCrypto.Bench` executem sem falhas.

## Guard‑rails e Tokens

- **Execução obrigatória**: rode os scripts `tools/guardrails/*.py` regularmente, especialmente antes de criar um release ou aprovar uma Pull Request.  Esses scripts verificam a ausência de dependências externas proibidas, a inexistência de stubs ou placeholders, a presença de tokens de recursos e a integridade do manifesto.
- **Atualização de tokens**: quando adicionar novas funcionalidades (por exemplo, wNAF, pré‑cálculo de G, witness preview, novos modos PSBT ou Miniscript), crie tokens correspondentes nas regras de guard‑rails e adicione‑os ao manifesto.  Assegure‑se de que `check_features.py` reconheça os novos recursos.
- **Correção imediata**: não ignore falhas de guard‑rails.  Qualquer violação deve ser corrigida antes de avançar.

## Documentação

- **Sincronização contínua**: atualize sempre os arquivos `README.md`, `docs/ARQUITETURA.md`, `docs/COMPLETUDE.md`, `CHANGELOG.md` e `ROADMAP.md` ao introduzir ou modificar funcionalidades significativas.
- **Notas de release**: crie um novo arquivo em `docs/` no formato `RELEASE_NOTES_X.Y.Z.md` para cada release, descrevendo de forma concisa o que mudou, o contexto e as melhorias implementadas.
- **Índice de documentos**: mantenha `docs/README_DOCS.md` atualizado com uma lista dos documentos existentes.  Remova entradas para arquivos que foram excluídos e adicione links para novos documentos.
- **Obsolescência**: elimine ou arquive documentos que deixaram de fazer sentido para as versões atuais.  Ao remover um documento, certifique‑se de atualizar referências em outras partes do repositório.

## Manifesto e Empacotamento

- Utilize o script `python tools/guardrails/package_release.py vX.Y.Z` para gerar pacotes consistentes.  Este script atualiza os manifestos (`MANIFEST_vX.Y.Z.txt`) e garante que apenas arquivos relevantes sejam incluídos.
- Revise o manifesto gerado e verifique se todos os arquivos essenciais (código fonte, scripts, documentação, testes e CMake) estão listados corretamente.
- Mantenha a versão do projeto consistente entre o código, o manifesto, o `CHANGELOG.md` e as notas de release.

## Testes e Benchmarks

- **Cobertura**: adicione vetores de teste (positivos e negativos) sempre que implementar novas rotas ou algoritmos.  Utilize testes de propriedade quando apropriado.
- **Rastreabilidade**: garanta que cada novo módulo ou função crítica tenha testes correspondentes no `BitCrypto.Tests`.
- **Benchmarks**: atualize `docs/BENCHMARKS.md` se forem adicionadas novas rotas de benchmark ou se otimizações significativas forem implementadas.  Execute `BitCrypto.Bench` em modos CPU e GPU para validar ganhos de performance.

## CI e Processo de Release

- **Integração contínua**: mantenha as configurações de CI (por exemplo, GitHub Actions) atualizadas.  Os jobs devem incluir guard‑rails, compilação, testes, benchmarks e empacotamento.
- **Releases**: siga as etapas descritas em `RELEASE_PROCESS.md` ao preparar uma nova versão.  Inclui atualizar o número de versão no código, gerar e revisar o changelog, criar notas de release e empacotar o artefato final.
- **Versionamento**: utilize semântica de versionamento (`X.Y.Z`).  Incrementos em `X` indicam alterações ou refatorações que quebram compatibilidade; `Y` adiciona funcionalidades de forma retrocompatível; `Z` inclui correções e melhorias internas.

## Governança e Responsabilidades

- **Mantenedores**: mantenha `MAINTAINERS.md` atualizado com o nome dos mantenedores e suas áreas de atuação.  Distribua responsabilidades de acordo com a expertise (e.g., Core/Hash, Tx/PSBT, GPU/Benchmarks).
- **Revisão**: todas as contribuições devem ser revisadas por ao menos um mantenedor.  O revisor deve assegurar a conformidade com estas diretrizes, qualidade de código, testes adequados e documentação.
- **Comunicação**: use o sistema de issues/PRs do repositório para discutir propostas, problemas e revisões.  Documente decisões de design e justificativas para futuras consultas.

Seguindo estas práticas, garantimos que o BitCrypto permaneça sustentável, seguro e pronto para evoluir conforme as necessidades do ecossistema Bitcoin e as metas definidas no roadmap.