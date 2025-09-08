# Convenções de Código

Este arquivo descreve convenções gerais para o código do BitCrypto.  Seguir estas diretrizes contribui para a legibilidade, manutenção e consistência entre módulos.

## Linguagem e Padrões

- Utilize **C++17** ou superior, conforme suportado pelo Visual Studio 2022.
- Prefira o uso de **RAII** para gerenciamento de recursos; evite ponteiros brutos quando houver alternativas (`std::unique_ptr`, `std::optional`, etc.).
- Preserve **const‑correctness** em funções e métodos.  Marque métodos como `const` quando não modificarem o estado observável.
- Utilize **`explicit`** em construtores de um único argumento para evitar conversões implícitas indesejadas.
- Considere **`noexcept`** em funções que não disparam exceções.

## Nomenclatura

- **Tipos** (classes, structs, enums) e namespaces utilizam **CamelCase** (e.g., `Transaction`, `KeyPair`).
- **Funções**, **variáveis** e **objetos** utilizam **snake_case** (e.g., `compute_hash`, `num_inputs`).
- Macros (quando inevitáveis) usam **UPPER_SNAKE_CASE** e devem ser limitadas a usos imprescindíveis.

## Organização de Arquivos

- Cada módulo (`BitCrypto.Core`, `BitCrypto.Hash`, etc.) deve ter seus arquivos de cabeçalho `.h` e implementação `.cpp` separados de forma lógica.
- Mantenha cabeçalhos livres de implementações extensas; prefira declarar funções e defini‑las nos `.cpp` correspondentes.

## Comentários e Documentação

- **Comentários** devem ser técnicos, em português, e explicar o racional, as invariantes e os passos não óbvios.  Evite comentários redundantes.
- Documente precondições, pós‑condições e qualquer requisito de constância no tempo.
- Adote o estilo `///` (Doxygen) para comentários de APIs quando apropriado.

## Erros e Exceções

- Evite exceções para controle de fluxo.  Utilize o tipo `Result<T>` ou enums de código de erro quando possível.
- Ao retornar códigos de erro, forneça mensagens breves que identifiquem o problema.

Seguir estas convenções ajuda a manter o BitCrypto coeso e compreensível para todos os colaboradores.
