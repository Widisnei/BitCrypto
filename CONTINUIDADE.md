# Continuidade do Projeto BitCrypto

Este documento estabelece diretrizes para a evolução contínua do BitCrypto.  Ele destina‑se a novos contribuidores e mantenedores, orientando sobre como propor novas funcionalidades, planejar releases e manter a coerência técnica do projeto ao longo do tempo.

## Leituras Obrigatórias

Antes de contribuir, familiarize‑se com os seguintes documentos:

- `README.md` — visão geral do projeto e seus módulos.
- `docs/ARQUITETURA.md` — descrição modular atualizada.
- `docs/COMPLETUDE.md` — resumo dos marcos já implementados.
- `REGRAS.md` — regras fundamentais do projeto (sem dependências externas, completude, não‑redundância, const‑time, etc.).
- `MAINTENANCE.md` — procedimentos de manutenção e release.

## Planejamento e Roadmap

- Use `ROADMAP.md` como fonte de verdade para o planejamento de marcos futuros.  Propostas de novas funcionalidades devem ser registradas como issues e, após discussão, refletidas no roadmap.
- Cada novo release deve ser acompanhado de uma entrada no `CHANGELOG.md` e um arquivo `docs/RELEASE_NOTES_X.Y.Z.md` detalhando as mudanças.  Mantenha também a seção “Novidades” do `README.md` atualizada.

## Propostas de Novos Módulos ou Funcionalidades

Ao propor uma nova funcionalidade ou módulo:

- **Justificativa**: explique o problema que está sendo resolvido e os benefícios para o projeto.
- **Integração**: demonstre como a nova funcionalidade se encaixa nos módulos existentes.  Evite sobreposição de responsabilidades e respeite o princípio de não‑redundância.
- **Impacto**: avalie o impacto em compatibilidade, segurança, desempenho (CPU/GPU) e código existente.  Indique se são necessárias alterações na API pública.
- **Plano de testes**: descreva como testará a nova funcionalidade (vetores canônicos, casos negativos, testes de propriedade) e, se aplicável, benchmarks.
- **Documentação**: proponha atualizações necessárias nos documentos (README, ARQUITETURA, COMPLETUDE, notes de release, etc.).
- **Tokens**: inclua tokens apropriados nos guard‑rails para as novas rotas/recursos.

## Princípios de Design e Qualidade

- **Não‑redundância**: implemente cada funcionalidade uma única vez; use abstrações para reutilizar código entre CPU e GPU quando possível.  Replicar código é aceitável apenas quando as diferenças de desempenho justificam.
- **Const‑time**: operações que envolvem chaves ou dados sensíveis devem ser independentes de segredo (tempo de execução e padrões de acesso).  Utilize `cswap/cmov` e outras técnicas de blindagem.
- **Completude**: evite stubs e placeholders.  APIs devem ser completas e ter interfaces estáveis.  Limitações conhecidas devem ser documentadas.
- **Código limpo**: siga as convenções descritas em `CONVENCOES_DE_CODIGO.md`, incluindo nomes autoexplicativos, RAII, tratamento de erros consistente e comentários técnicos em português.

## Revisão e Aprovação

- Pull Requests devem incluir descrição clara, referência a issues (quando houver), testes e documentação atualizada.
- O revisor deve verificar que os guard‑rails e testes são executados sem falhas e que a proposta se alinha ao roadmap e às regras do projeto.
- Mudanças que alterem APIs públicas ou quebrem compatibilidade devem ser discutidas amplamente e planejadas em releases principais (mudança de versão `X`).

## Deprecação e Remoção de Funcionalidades

- Ao remover ou substituir uma funcionalidade, documente a deprecação nas notas de release e, se possível, forneça uma rota de migração.
- Remova código e documentação obsoletos para evitar confusão.  Mantenha registros apenas no histórico do repositório.

## Continuidade Organizacional

- Atualize `MAINTAINERS.md` quando houver mudança de equipe ou responsabilidades.  Mantenha clara a divisão de áreas de atuação.
- Incentive a transferência de conhecimento através de revisões e discussões abertas.  Evite que conhecimento crítico fique concentrado em uma única pessoa.

## Plano de Continuidade — Próximos Passos

Além das diretrizes organizacionais acima, o BitCrypto possui um conjunto de trabalhos técnicos pendentes que completam o escopo pretendido para as futuras versões da biblioteca.  Estes pontos se baseiam em técnicas empregadas por bibliotecas de referência como **libsecp256k1**, **libbitcoin** e **OpenSSL**, bem como em propostas recentes de BIPs e algoritmos mais rápidos.

### 1. Multi‑Scalar Multiplication (MSM)

Concluído na versão **v2.5.0** com base na rotina de Pippenger do **libsecp256k1**.  O BitCrypto agora dispõe de uma função `msm(points[], scalars[])` em `BitCrypto.Core` que seleciona janelas adaptativas, recodifica escalares via **wNAF** e permite reutilizar tabelas em um contexto opcional de **precompute**.

### 2. Endomorfismo e Truque de Shamir

Implementados na **v2.5.0** com referência ao **libsecp256k1**.  A decomposição de escalar `split_scalar_lambda()` reduz `s·P` a duas multiplicações menores, e o helper `shamir_trick()` combina `a·P + b·G` em uma única passagem de wNAF apoiada pelo MSM Pippenger.

### 3. Assinaturas Agregadas e FROST

Com MSM, endomorfismo e Shamir prontos, pode‑se implementar assinaturas agregadas e threshold.  As propostas de BIP‑340/341 já suportam **MuSig2** (agregação de chaves e assinaturas Schnorr) e existem protocolos **FROST** para threshold Schnorr.  As tarefas incluem:

- Adicionar suporte a **MuSig2**: geração de chave agregada, combinação de *nonces* e produção/validação da assinatura agregada.  Isso exigirá operações `msm()` para somar múltiplos `sᵢ·Pᵢ` durante a agregação.
- Implementar um protótipo de **FROST** para `t‑of‑n` assinaturas Schnorr.  Inclui criação de compromissos, distribuição de coeficientes de Lagrange e verificação das assinaturas parciais.  A biblioteca deve fornecer apenas a primitiva criptográfica; a orquestração multi‑party pertence a camadas superiores.
- Criar vetores de teste e exemplos de CLI (`--musig2-sign`, `--musig2-verify`, `--frost-sign`, etc.) para demonstrar o uso das APIs.

### 4. BIPs Recentes e Mensagens Gerais

Além das transações, o projeto deve contemplar a padronização de assinatura de mensagens gerais.  O **BIP‑322** define um formato unificado de mensagem que pode ser assinado e verificado em qualquer tipo de endereço (P2PKH, P2WPKH, P2TR).  Para suportá‑lo:

- Implementar rotinas de assinatura/verificação conforme o BIP‑322, incluindo o cálculo do **hash_for_message**, a derivação do script apropriado e a verificação de witness.  Diferente do `signmessage` antigo, o BIP‑322 usa scripts de transação fictícia para unificar P2PKH/P2WPKH/P2TR.
- Adicionar um comando de CLI `--sign-message`/`--verify-message` aceitando mensagens e endereços, retornando a assinatura BIP‑322 no formato base64.

### 5. Testes, Benchmarks e GPU

Cada novo algoritmo deve vir acompanhado de testes extensivos: vetores positivos e negativos, testes de propriedade (por exemplo, verifique que `msm([P], [s]) == s·P` para diferentes entradas), e comparações de desempenho.  O Pippenger permite paralelismo; portanto, investigue a implementação de MSM na GPU utilizando blocos e *shuffle* intrinsics.  A Regra 3 continua válida: a implementação GPU deve duplicar código apenas se o ganho de performance justificar e todos os testes de equivalência CPU/GPU devem passar.

### 6. Referências e Observações

- Paul Miller discute o algoritmo **wNAF** e seus pré‑cálculos, destacando que o wNAF usa adição e subtração para reduzir o número de pontos precomputados e que a janela 4 requer 520 pontos de precomputação, enquanto uma janela 8 requer 4224 pontos【481458509835048†L575-L593】.
- Jared Tobin observa que o wNAF exige um **contexto** contendo muitas multiplicações de `G`, o que complica a API mas resulta em grandes ganhos de desempenho【411223492370334†L14-L24】.  Este contexto deve ser explicitamente inicializado e passado para as operações quando necessário.
- A documentação do libsecp256k1 lista técnicas de otimização, incluindo uso de wNAF com janelas maiores para `G`, Shamir's trick, endomorfismo para dividir o escalar e tabelas de pré‑cálculo com movimento condicional para acesso constante【299153663448862†L391-L408】.  Estas estratégias devem inspirar a evolução do BitCrypto, respeitando as restrições de não‑dependência e const‑time.

Integrando as tarefas acima com os princípios de design descritos anteriormente, o BitCrypto avançará em direção a uma biblioteca completa, performática e alinhada aos padrões mais modernos do ecossistema Bitcoin.

Seguindo estas orientações e realizando os trabalhos técnicos planejados, contribuiremos para que o BitCrypto continue evoluindo de forma ordenada, coesa e sustentável, mesmo com a entrada de novos colaboradores e a saída de membros antigos.