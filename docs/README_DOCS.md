# Documentação — BitCrypto (consolidado em 2025‑09‑08)

Este diretório contém documentos complementares à documentação principal do projeto.  Os arquivos de versão e planejamento (como **CHANGELOG.md**, **ROADMAP.md** e **AGENTS.md**) residem na raiz do repositório.  Nesta pasta você encontrará notas de release, aceites de QA, guias de linha de comando e registros históricos das versões anteriores.

## Visão geral

- **Notas de release (`RELEASE_NOTES_*.md`)** — descritivo das mudanças em cada versão 2.x (ex.: `RELEASE_NOTES_2.5.0.md`).
- **Aceites de QA (`ACEITE_QA_*.md`)** — checklists de testes de fumaça e de guard‑rails para cada release.
- **Guia de CLI (`CLI_GUIDE.md`)** — resumo das opções disponíveis nas ferramentas de linha de comando (MSCLI, PSBTCLI, WSCLI, Bench, etc.).
- **Benchmarks (`BENCHMARKS.md`)** — instruções sobre como executar e interpretar os benchmarks de throughput.
- **Completude (`COMPLETUDE.md`)** — resumo dos marcos já implementados até a versão 2.5.0.
- **Arquitetura (`ARQUITETURA.md`)** — descrição modular da biblioteca na versão 2.5.0.
- **Componentes (`DESCRICAO_COMPONENTES.md`)** — resumo detalhado do propósito e da implementação de cada módulo (Core, Hash, Encoding, KDF/HD, Sign, Tx & PSBT, GPU, Tests & Bench).
- **Documentação avançada (`REFERENCIAS_AVANCADAS.md`)** — guia de pesquisa e referências externas sobre algoritmos de otimização (wNAF, endomorfismo, truque de Shamir, algoritmo de Pippenger); técnicas avançadas utilizadas por bibliotecas de criptografia do GitHub e de referência (Crypto++, Paillier, HEXL, Botan, WolfCrypt, além das bibliotecas **secp256k1**, **libbitcoin‑system**, **Kangaroo** e **OpenSSL**); e novidades do CUDA 13, além de princípios de segurança.
- **Documentos históricos** — os planos de construção, os documentos de implementação e os fluxos de planejamento das versões 0.x/1.x foram **removidos** deste diretório para reduzir ruído. Esses arquivos antigos estão disponíveis apenas no histórico Git. Para obter informações atualizadas, consulte este README, o `ARQUITETURA.md`, as notas de release e o roadmap.

Para mais detalhes sobre regras de projeto, modelo de segurança e planejamento futuro, consulte os arquivos na raiz (`README.md`, `CHANGELOG.md`, `ROADMAP.md`, `SECURITY.md`, `AGENTS.md`, `MAINTENANCE.md`, `CONTINUIDADE.md` e `MAINTAINERS.md`).