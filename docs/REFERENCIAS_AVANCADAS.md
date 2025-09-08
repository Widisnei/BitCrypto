# Documentação avançada e referências

Este documento consolida referências de pesquisa e conceitos avançados necessários para desenvolver e manter BitCrypto conforme a sua estrutura modular.  Ele complementa a documentação existente, fornecendo fontes externas e contexto para algoritmos usados no projeto.

## Multiplicação escalar e métodos de otimização

### Precomputação e wNAF

O método **w‑ary Non‑Adjacent Form (wNAF)** é usado para acelerar a multiplicação escalar do ponto base.  Em vez de realizar 256 somas de pontos para cada bit da chave, ele divide o escalar em janelas de 4/8/16 bits e pré‑computa potências do ponto base.  Isso reduz o número de operações: é preciso armazenar **520 (W=4), 4224 (W=8) ou 557 056 (W=16) pontos** pré‑computados, economizando metade da memória e reduzindo pela metade o tempo de inicialização graças ao uso de adição e subtração (a negação de um ponto pode ser feita em tempo constante)【203718979069324†L575-L591】.  Bibliotecas como **libsecp256k1** utilizam uma forma ainda mais eficiente de wNAF (com janelas maiores para o ponto base) e uma tabela pré‑computada de 16×G, acessada em tempo constante com `cmov`【299153663448862†L391-L408】.

### Contexto de pré‑cálculo

Implementações que usam wNAF precisam de um **contexto** com as potências pré‑computadas do ponto base.  Jared Tobin observa que o único inconveniente da abordagem é a necessidade de passar um argumento de contexto contendo múltiplos pré‑computados de G; isso complica um pouco a API, embora permita melhorias de até **7,5×** na assinatura ECDSA e quase **2×** na verificação【368584739763539†L18-L23】.

### Endomorfismo e decomposição GLV

A curva secp256k1 admite um **endomorfismo** eficiente (GLV).  A técnica de decomposição GLV divide um escalar `k` em dois sub‑escalares (`k₁` e `k₂`) de aproximadamente metade do tamanho.  O ponto é transformado via a função ψ: `ψ(P) = (β·x mod p, y)`, e o escalar é decomposto como `k ≡ k₁ + λ·k₂ (mod n)`.  A multiplicação `k·P` é então realizada como `k₁·P + k₂·ψ(P)`, permitindo substituir uma multiplicação de 256 bits por duas multiplicações de 128 bits e uma soma【203718979069324†L681-L693】.  Um estudo sobre verificação de ECDSA mostra que o **método GLV** reduz a multiplicação escalar a uma multiescalar com dois sub‑escalares; estes são processados simultaneamente pelo **truque de Shamir**, resultando em ganhos de aproximadamente **16% a 30%** em relação aos métodos tradicionais【443391913575489†L107-L117】.

### Truque de Shamir (Strauss–Shamir)

O **truque de Shamir** (ou método de Strauss) permite calcular duas multiplicações escalares simultaneamente (`u₁·P + u₂·Q`) de forma mais eficiente do que computá‑las separadamente.  O libsecp256k1 aplica esta técnica ao verificar assinaturas, combinando‑a com o wNAF e o endomorfismo para reduzir o número de somas de pontos【299153663448862†L391-L408】.

### Multi‑escalares e algoritmo de Pippenger

Para operações que envolvem múltiplos pares escalar‑ponto (como agregação de assinaturas ou somatórios de chaves públicas), usa‑se a **multiplicação multi‑escalar (MSM)**.  O **algoritmo de Pippenger** (também chamado de método de bucket) é uma abordagem eficiente para MSM: ele divide cada escalar em blocos de `s` bits e agrupa termos com índices semelhantes em “baldes”, acumulando as somas parciais e combinando‑as na fase final.  Jonathan Bootle explica que o objetivo do algoritmo é computar um produto `G = ∑_{i=0}^{N−1} g_i^{e_i}` de maneira mais eficiente do que calcular cada potência individualmente【750135611335162†L4-L6】.  Em implementações modernas, Pippenger é a base de bibliotecas de MSM e pode ser paralelizado em CPU ou GPU.

## Considerações de segurança e implementação

### Operações em tempo constante

Implementações criptográficas devem evitar ramificações dependentes de dados e acessos a memória que revelem informação secreta.  A **Bitcoin Cryptography Library** de Nayuki implementa aritmética de campo (`FieldInt`), números grandes (`Uint256`), pontos de curva (`CurvePoint`) e ECDSA inteiramente em tempo constante, mitigando ataques de tempo e de cache【200806843580729†L157-L166】.  A biblioteca também usa **coordenadas projetivas** e a **redução Barrett** para acelerar as operações de curva【200806843580729†L190-L200】.  O BitCrypto adota princípios similares: todas as funções críticas devem ser executadas em tempo constante e usar técnicas como `cmov` para substituir condicionais.

### Referências e comparações

- **libsecp256k1** – Biblioteca C de referência para secp256k1; implementa wNAF, Shamir e endomorfismo com janelas grandes, tabelas pré‑computadas e `cmov` para acesso constante aos múltiplos【299153663448862†L391-L408】.
- **Nayuki Bitcoin Cryptography Library** – Implementação em C++ com foco em segurança e legibilidade; utiliza coordenadas projetivas, redução Barrett e operações constant‑time【200806843580729†L157-L166】【200806843580729†L190-L200】.
- **Publicações acadêmicas** – O estudo de Manju et al. descreve o método GLV e o truque de Shamir para acelerar a verificação ECDSA【443391913575489†L107-L117】, enquanto Jonathan Bootle detalha o algoritmo de Pippenger para multi‑exponentiação【750135611335162†L4-L6】.

## Recomendações para desenvolvimento

1. **Consulte as fontes** – Antes de implementar otimizações, consulte os artigos e documentos citados aqui para compreender os algoritmos e suas condições de segurança.
2. **Preserve a modularidade** – Cada componente (Core, Hash, Encoding, KDF/HD, Sign, Tx/PSBT, GPU, Benchmarks) deve permanecer autocontido e documentado em `DESCRICAO_COMPONENTES.md`.
3. **Atualize a documentação** – Ao adicionar um algoritmo (p.ex. Pippenger, MuSig2, FROST), atualize `REGRAS.md`, `CONTINUIDADE.md` e este documento com referências apropriadas.
4. **Manter operações constant‑time** – Nunca introduza ramificações dependentes de chaves ou outros dados secretos.
5. **Revisar dependências** – Verifique se novas bibliotecas estão alinhadas com as práticas de segurança e performance adotadas aqui.

---

Este documento é um guia de consulta para manter e evoluir o BitCrypto com base em técnicas bem‑estabelecidas na literatura.  Consulte‑o sempre que houver dúvidas sobre algoritmos ou decisões de design.

## Técnicas avançadas em bibliotecas de criptografia do GitHub

Nos repositórios públicos de criptografia hospedados no GitHub é possível encontrar bibliotecas que aplicam otimizações sofisticadas para obter alto desempenho em diferentes arquiteturas de hardware.  Esta seção resume algumas dessas técnicas, oferecendo referências externas para estudo:

### Crypto++ (cryptopp)

O **Crypto++** é uma biblioteca de propósito geral que implementa diversos algoritmos simétricos e assimétricos.  Além do conjunto de primitivas, ele oferece otimizações específicas de cada arquitetura.  O README observa que a biblioteca possui código *in‑core* otimizado para **x86, x64, x32, ARM‑32, Aarch32, Aarch64 e Power8**, com **detecção de funcionalidades de CPU em tempo de execução** e **seleção automática de código otimizado**【952821229813287†L99-L106】.  Para cada plataforma, utiliza instruções vetoriais adequadas:

- **x86/x64/x32**: implementações com **MMX, SSE2 e SSE4**【952821229813287†L99-L106】;
- **ARM‑32/Aarch32/Aarch64**: suporte a **NEON** e extensões **ASIMD/ARMv8**【952821229813287†L99-L106】;
- **Power8**: uso da aceleração **NX Crypto** para AES【952821229813287†L99-L106】.

Esses trechos demonstram como Crypto++ escolhe implementações específicas para cada ISA e detecta recursos em tempo de execução para maximizar a performance.

### Intel Paillier Cryptosystem Library

A biblioteca **Paillier Cryptosystem Library**, da Intel, é um exemplo de aceleração aplicada a criptografia homomórfica.  O README explica que a implementação utiliza o **IPP Crypto** (Integrated Performance Primitives) para realizar **exponenciação modular em “multi‑buffer”** (`mbx_exp_mb8`), explorando instruções **AVX512IFMA** em CPUs Ice Lake【323751910045844†L37-L45】.  A recomendação é executar a biblioteca em sistemas com AVX512IFMA para maior desempenho; contudo, se as instruções não estiverem presentes, o código alterna automaticamente para uma implementação sem multi‑buffer【323751910045844†L48-L56】.

### Intel HEXL – Homomorphic Encryption Acceleration Library

Outra biblioteca da Intel voltada a criptografia homomórfica, a **HEXL**, acelera aritmética polinomial em campos finitos.  Para multiplicar polinômios grandes, ela implementa a **transformada número‑teórica negacíclica (NTT)** e expõe funções de multiplicação vetorial e escalar.  Para cada função, o projeto disponibiliza **várias implementações usando AVX‑512**, além de uma versão em C++ puro.  O código **seleciona automaticamente a melhor versão** dependendo das funcionalidades AVX‑512 do processador; quando o módulo `q` é menor que `2^{50}`, a instrução **AVX512IFMA** nos processadores Ice Lake é mais eficiente【887805735544057†L82-L88】.

### Botan

A biblioteca C++ **Botan** também emprega extensões de hardware para acelerar primitivas criptográficas.  A documentação observa que o código da biblioteca utiliza **AES‑NI e AVX2 no x86**, bem como **NEON e as extensões criptográficas do ARMv8** em Aarch64, selecionando arquivos de código diferentes conforme o processador【686068487966041†L1178-L1183】.  Essa abordagem garante que algoritmos como AES se beneficiem de instruções vetoriais quando disponíveis.

### WolfSSL/WolfCrypt (GPU)

Bibliotecas como **wolfCrypt** (parte do projeto wolfSSL) exploram a computação **CUDA** para acelerar criptografia.  Em GPUs NVIDIA, o wrapper intercepta chamadas de funções de criptografia (como `AesEncrypt_C` e `AesEncryptBlock_C`) e offloada os blocos de dados para o dispositivo.  Como resultado, modos paralelizáveis de AES (ECB, GCM, XTS, CTR) obtêm **acelerações de 1,6× a 10,8×** em GPUs A‑series e **até 5,3×** em GPUs H100, enquanto modos com dependências sequenciais (CBC, CFB, OFB, CCM, SIV, CMAC) não se beneficiam【651329354426620†L55-L74】.  Essa técnica demonstra como dividir cargas em blocos independentes pode melhorar significativamente o throughput criptográfico.

### Implementações GPU de AES com T‑boxes

Pesquisadores também exploram a aceleração de AES em GPU utilizando **esquemas de T‑box** e alocação em memória compartilhada.  Um estudo mostra que, atribuindo **um estado por thread** e realizando **lookups em T‑box na memória compartilhada**, é possível atingir **207 Gbps** no TITAN X e **280 Gbps** no GTX 1080 com granularidade de 32 bytes por thread【103884807440620†L15-L56】.  A mesma abordagem, combinada com uma biblioteca de aritmética de múltipla precisão em CUDA, alcançou **cerca de 60 Gbps** no Tesla C2050, com aceleração de até **50×** em relação à CPU【103884807440620†L74-L87】.

## CUDA 13 — técnicas e melhorias

A versão **CUDA 13** é uma atualização significativa da plataforma de desenvolvimento da NVIDIA.  Seguem os recursos importantes para quem utiliza GPUs para acelerar criptografia e outras tarefas:

### Alinhamento e gerenciamento de registradores

O CUDA 13 introduz **vetores alinhados de 32 bytes**, melhorando o rendimento de carregamento e armazenamento na arquitetura **Blackwell**【543889247508124†L112-L116】.  Há também **escalonamento otimizado** e **spilling de registradores para memória compartilhada**, reduzindo a latência de kernels com alta densidade de registradores【543889247508124†L115-L118】.

### Unificação para plataformas Arm e novas ferramentas

O toolkit passa a oferecer um **toolchain unificado** para plataformas Arm, incluindo o **Grace Hopper** e o **Jetson Thor**, simplificando a compilação cruzada【543889247508124†L119-L126】.  Suporte a sistemas operacionais recentes (Ubuntu 24.04, RHEL 10, Fedora 42, Rocky Linux 10) e compiladores **GCC 15** e **Clang 20** foi adicionado【543889247508124†L128-L133】.  A compressão de binários mudou para o **Zstandard**, e a infraestrutura de **CUDA Graphs** recebeu melhorias para workloads dinâmicos【543889247508124†L134-L138】.  Ferramentas como o **Compile Time Advisor (ctadvisor)** ajudam a otimizar configurações de build, e as bibliotecas **cuBLAS, cuFFT, cuSPARSE e cuSOLVER** foram atualizadas com foco em precisão e desempenho【543889247508124†L142-L145】.  O **runtime** agora pode carregar contextos sem inicialização explícita, simplificando a integração【247263132036739†L45-L50】.

### Melhorias de desempenho e depuração

O CUDA 13.0 aumenta o limite de clientes do **MPS (Multi‑Process Service)** de 48 para **60 clientes** em GPUs Ampere e posteriores【680880356704772†L905-L915】, permitindo maior compartilhamento de GPU entre processos.  O runtime substitui a compressão *fatbin* de **LZ4 para Zstd**, melhorando a eficiência no tamanho do binário sem penalizar a execução【247263132036739†L45-L50】.  Relatórios de erros e diagnósticos foram aprimorados para facilitar o desenvolvimento e a depuração【543889247508124†L134-L138】.

### Depreciações e mudanças na API

A documentação oficial destaca a **depreciação dos tipos vetoriais legados** (`double4`, `long4`, `ulong4`, etc.), que serão removidos no CUDA 14.0; eles foram substituídos por variantes alinhadas `*_16a` e `*_32a`【680880356704772†L942-L967】.  A API de **multi‑device launch** foi removida, e vários campos antigos de `cudaDeviceProperties` foram eliminados, com recomendações de APIs de substituição【680880356704772†L971-L1031】.  Finalmente, o suporte a arquiteturas **Maxwell, Pascal e Volta** foi descontinuado; essas arquiteturas são consideradas “feature‑complete” e não recebem novas otimizações【680880356704772†L1044-L1051】.

Estas mudanças tornam o CUDA 13 mais focado em GPUs modernas (Turing, Ampere, Hopper e Blackwell) e fornecem bases para otimizações de criptografia que exploram alinhamento vetorial, menor latência e bibliotecas atualizadas.

## Bibliotecas de referência

A seguir, descrevemos técnicas e características avançadas observadas em quatro bibliotecas de referência amplamente usadas para criptografia de curva elíptica e infraestrutura Bitcoin.  Essas bibliotecas ilustram implementações maduras e fornecem inspiração para otimizações e boas práticas ao evoluir o BitCrypto.

### secp256k1 (Bitcoin Core)

O projeto **[secp256k1](https://github.com/bitcoin-core/secp256k1)** é uma biblioteca C otimizada e de alta segurança para operações na curva de mesmo nome.  A implementação de verificação de assinaturas ECDSA/Schnorr utiliza diversas técnicas:

- **Notação wNAF e janelas grandes** — Para multiplicações escalares de verificação (`a·P + b·G`), a biblioteca usa a notação wNAF e um **tamanho de janela maior para o ponto base G**, possibilitando pré‑computar múltiplos de G【493743274359748†L74-L77】.
- **Truque de Shamir e endomorfismo** — A verificação usa o **truque de Shamir** para calcular `a·P + b·G` simultaneamente e aplica a decomposição de **endomorfismo** para dividir a multiplicação de P em dois multiplicadores de metade do tamanho【493743274359748†L78-L81】.
- **Pré‑cálculo e `cmov`** — Para operações de assinatura, é usada uma tabela pré‑computada de múltiplos de 16×G; o acesso é feito por **movimentos condicionais (`cmov`)**, evitando ramificações e acessos de memória dependentes da chave.  Há ainda a opção de **cegar em tempo de execução** a chave para mitigar ataques de canal lateral【493743274359748†L82-L90】.

Essas técnicas, combinadas com aritmética de campo otimizada, fazem da libsecp256k1 uma referência para desempenho e segurança em secp256k1.

### libbitcoin‑system

O **[libbitcoin‑system](https://github.com/libbitcoin/libbitcoin-system)** não é uma biblioteca de baixo nível para aritmética de curva, mas sim um **toolkit C++ para desenvolvimento de aplicações Bitcoin**.  Sua arquitetura foca em escalabilidade e disponibilidade: cada componente possui **seu próprio pool de threads**, permitindo **escalar o processamento distribuindo as tarefas entre múltiplos núcleos**【781610187074502†L12-L22】.  O **Libbitcoin Server** expõe uma API de consulta sobre blockchain e utiliza a pilha de rede **ZeroMQ** e a biblioteca **libsodium** para encriptação e autenticação de conexões, com suporte opcional a certificados de identidade de servidor/cliente【781610187074502†L33-L41】.  Essas escolhas demonstram uma abordagem assíncrona e modular, priorizando desempenho e privacidade.

### Pollard’s Kangaroo (JeanLucPons/Kangaroo)

O repositório **[Kangaroo](https://github.com/JeanLucPons/Kangaroo)** implementa um **resolvedor do problema do logaritmo discreto (ECDLP) com o método do canguru de Pollard** para a curva secp256k1.  O projeto se destaca por:

- **Aritmética de tamanho fixo** com **inversão modular rápida** (utilizando deslocamento à direita retardado de 62 bits) e **multiplicação modular rápida** (duas etapas de redução de 512 bits para 256 bits usando dígitos de 64 bits)【102758968128271†L6-L13】.
- **Suporte a múltiplas GPUs** e **otimizações CUDA** com **assembly PTX inline** para acelerar a execução em placas NVIDIA【102758968128271†L13-L15】.
- **Método dos pontos distintos (DP)** — O algoritmo usa o método de **pontos distintos** para reduzir o armazenamento de caminhadas aleatórias: somente são salvos pontos cujas coordenadas começam com um certo número de bits zero.  Esse método diminui a memória necessária mas pode aumentar o overhead em faixas de busca pequenas【102758968128271†L83-L99】.

Embora não seja parte do BitCrypto, esse projeto demonstra como o paralelismo massivo de GPUs e técnicas de redução de memória podem ser aplicados ao ECDLP.

### OpenSSL

O projeto **[OpenSSL](https://github.com/openssl/openssl)** fornece uma **biblioteca robusta para TLS/DTLS/QUIC** e um **módulo criptográfico de uso geral (`libcrypto`)**, ambos utilizados em sistemas críticos ao redor do mundo【501317707346924†L50-L60】.  Destacam‑se as seguintes características avançadas:

- **Módulos em assembly e aceleração por instruções** — O processo de compilação do OpenSSL inclui **rotinas em assembly que utilizam extensões de CPU como AES‑NI, PCLMULQDQ, SSSE3 e SHA**, garantindo que essas otimizações sejam sempre montadas quando suportadas【608457601775376†L2184-L2190】.  Isso resulta em aceleração significativa para algoritmos como AES e SHA nas plataformas x86_64.
- **Detecção dinâmica de arquitetura** e **despacho em tempo de execução** — Com base na variável `OPENSSL_ia32cap` (não listada aqui), o OpenSSL identifica as capacidades da CPU em tempo de execução e seleciona rotinas otimizadas para AVX, AVX2 ou AVX‑512; a documentação inclusive especifica versões mínimas de `gnu as`, `nasm` e `llvm` necessárias para compilar esses caminhos【608457601775376†L2184-L2201】.
- **Ampla cobertura de protocolos e modos** — O toolkit implementa todas as versões do TLS até **TLS 1.3**, DTLS até 1.2 e **QUIC**, além de expor funcionalidades de linha de comando para geração de chaves, certificados, digests, assinaturas e encriptação【501317707346924†L52-L69】.

Esses recursos fazem do OpenSSL uma biblioteca versátil e de alta performance, servindo de referência para otimizações de hardware e compatibilidade com diversos protocolos.

---

Essas descrições complementam o panorama de otimizações apresentado anteriormente e fornecem fontes de inspiração para evoluir o BitCrypto.  Ao estudar essas implementações de referência, mantenha em mente os princípios de segurança (operações em tempo constante, ausência de dependências externas sensíveis) e as necessidades específicas do projeto.
