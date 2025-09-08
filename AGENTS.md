# AGENTS — Diretrizes de Continuidade (v2.5.0)

- Respeitar as **Regras do Projeto** (sem deps externas; VS2022/Win11 x64/CUDA 13; implementações completas; comentários PT‑BR; pacote + manifesto a cada entrega). 
- Antes de abrir PR/entrega, rodar os **guard‑rails**: `tools/guardrails/*.py`.
- Para empacotar: `python tools/guardrails/package_release.py vX.Y.Z`.
- Estender Miniscript de forma incremental, com testes (incluindo negativos) a cada combinador novo.
- PSBT v2: manter signer/verifier coesos e *pretty-printer* útil para diagnóstico.
- Tapscript: usar `CHECKSIGADD` em `thresh()`; preferir árvores simples inicialmente.

## Versão 2.5.0

- Atualizar e validar tokens de guard‑rails para novas otimizações (**wNAF/precompute** e **witness preview**); rodar `tools/guardrails/check_features.py` sempre que um recurso for adicionado.
- Para melhorias de desempenho (ex.: unrolling de SHA‑256, janelas wNAF), garantir que a implementação continue sem dependências externas e const‑time nas rotas sensíveis.
- Em módulos GPU, respeitar a Regra 3 de não‑redundância: duplicar código apenas quando o ganho de performance justifica; manter testes de equivalência CPU↔GPU.
- Manter a documentação sincronizada (README, ARQUITETURA, COMPLETUDE, ROADMAP e notas de release) a cada entrega, removendo ou marcando como histórico documentos obsoletos.

## Próximos marcos (visão do agente)

O agente deve se preparar para implementar funcionalidades planejadas no *Plano de Continuidade*.  Em particular:

- **MSM / Pippenger**: adicionar suporte a multiplicação multi‑escalar em `BitCrypto.Core` com janelas adaptativas.  Fornecer um contexto de pré‑cálculo opcional para reutilizar tabelas de pontos e permitir APIs que recebam listas de pontos e escalares.
- **Endomorfismo e Shamir**: criar rotinas de decomposição de escalar (endomorfismo) e combinação de multiplicações (Shamir's trick) para acelerar verificações de assinatura.  Documentar o uso e garantir const‑time.
- **MuSig2 e FROST**: implementar assinatura agregada e threshold utilizando Schnorr BIP‑340.  Incluir funções de agregação de chave, combinação de nonces e verificação de assinaturas parciais.  Disponibilizar opções na CLI.
- **BIP‑322**: suportar a assinatura e verificação de mensagens genéricas, aceitando qualquer tipo de endereço.  Criar comandos `--sign-message`/`--verify-message` e atualizar a documentação.

Para cada uma dessas etapas, o agente deverá atualizar a documentação (`CONTINUIDADE.md`, `ARQUITETURA.md`, `COMPLETUDE.md`) e os guard‑rails (novos tokens) e incluir testes.  Consulte `CONTINUIDADE.md` para uma lista detalhada de tarefas e referências.

## Instruções para o Codex IA

Esta seção destina‑se ao agente de IA (Codex IA) responsável por gerar e manter o código do BitCrypto.  Os itens a seguir sintetizam as principais regras, processos e futuros marcos que o agente deve seguir.  Eles complementam as diretivas gerais do projeto presentes neste arquivo e nos demais documentos (`REGRAS.md`, `CONTINUIDADE.md`, `MAINTENANCE.md`, `CONVENCOES_DE_CODIGO.md` e `REFERENCIAS_AVANCADAS.md`).

1. **Seguir as Regras** — O Codex deve sempre respeitar as regras do projeto: zero dependências externas, C++17, operações em tempo constante para rotas sensíveis, comentários em português, uso de CMake/VS2022 x64/CUDA 13 conforme os presets.  Antes de propor mudanças, consulte e atualize `REGRAS.md` e `CONVENCOES_DE_CODIGO.md`.

2. **Guard‑rails e testes** — Antes de finalizar uma tarefa, rode os scripts de guard‑rails (`tools/guardrails/check_constant_time_heuristic.py`, `check_no_external_deps.py`, etc.) e execute os testes (`ctest`).  Se adicionar novos algoritmos ou módulos, forneça tokens e assinaturas de guard‑rails adequados.

3. **Empacotamento e CI** — Use o script `package_release.py` para gerar os zips e manifests de releases.  Mantenha a configuração do CMake (`CMakeLists.txt` e `CMakePresets.json`) e os workflows do GitHub Actions atualizados, garantindo builds reproduzíveis (RelWithDebInfo por padrão, LTO opcional, CUDA opcional).  Nunca comprometa a estabilidade do CI.

4. **Documentação** — Para cada novo recurso implementado, atualize os arquivos de documentação correspondentes: `CONTINUIDADE.md` (planejamento futuro), `COMPLETUDE.md` (cobertura atual), `ARQUITETURA.md`/`DESCRICAO_COMPONENTES.md` (descrição de módulos), `README.md` e notas de release.  Referencie fontes externas (vide `REFERENCIAS_AVANCADAS.md`) quando introduzir novas técnicas e registre marcos atingidos.

5. **Tarefas de evolução** — Prepare‑se para implementar as funcionalidades listadas em **Próximos marcos**, incluindo:
   - Suporte a **multiplicação multi‑escalar (Pippenger)** com contexto de pré‑cálculo em `BitCrypto.Core`.
   - Implementação de **endomorfismo/GLV** e **Shamir's trick** para melhorar verificações de ECDSA/Schnorr.
   - Suporte às assinaturas agregadas **MuSig2** e **FROST**, com comandos de CLI para agregação, assinatura e verificação.
   - Implementação de **BIP‑322** para assinatura de mensagens genéricas.
   - Integração de novos módulos e refatoração de Miniscript/PSBT conforme o roadmap.

6. **Qualidade e segurança** — Mantenha o código legível, modular e coberto por testes.  Preserve operações em tempo constante, evite instruções dependentes de dados e utilize `cmov` quando necessário.  Antes de adotar novas otimizações (p.ex., unrolling, janelas wNAF), consulte `REFERENCIAS_AVANCADAS.md` e justifique o ganho de performance sem quebrar as regras.

Seguindo estas diretrizes, o Codex IA será capaz de continuar a evolução do BitCrypto de forma consistente e segura.
