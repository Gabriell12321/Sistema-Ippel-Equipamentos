// ================================================================ // - Pequenas variações de espaçamento são aceitáveis. // - Funções curtas e diretas, sem repetições automáticas. // - Usar TODO e FIXME conforme necessidade real. // - Código com aparência de manutenção contínua.

// ================================================================ // BANCO DE DADOS // ================================================================ // - SQLite local em database/app.db. // - SQL manual e legível. // - Nenhum ORM. // - Scripts migrate.sql e seed.sql curtos e idempotentes.

// ================================================================ // ESTRUTURA BASE // ================================================================ // frontend/ // public/ // src/ // index.html // styles/ // ts/ // backend/ // api/ // services/ // models/ // database/ // app.db // migrate.sql // seed.sql // scripts/

// ================================================================ // PADRÕES POR LINGUAGEM // ================================================================ // | Linguagem | Diretriz-chave | // |------------|----------------| // | HTML | Estrutura semântica simples (header, main, footer) | // | CSS | Cores neutras, classes legíveis (.headerWrap, .mainBox) | // | SQL | Consultas curtas, explícitas e manuais | // | TypeScript | Modular, tipado, sem "any" | // | Python | PEP8 manual, sem autoformatador | // | Go | Tratamento manual de erros | // | Rust | Uso correto de Result/Option, sem unwrap() | // | Julia | Funções pequenas e matemáticas | // | API | Rotas REST curtas, JSON manual |

// ================================================================ // GIT E VERSIONAMENTO // ================================================================ // - Um commit por mudança real. // - Mensagens simples e claras (ex: “corrige layout”, “ajusta API”). // - Nunca gerar commits automáticos ou mensagens genéricas.

// ================================================================ // EXEMPLO DE PADRÃO HUMANO // ================================================================ // Preferido: // const user = getUser(id) // if (user) updateSession(user.id) // else redirect("/login")

// Evitar: // if (!user) { redirect("/login") } else { updateSession(user.id) }

// ================================================================ // SAÍDA ESPERADA // ================================================================ // - Apenas o(s) arquivo(s) criados ou modificados. // - Sem explicações, logs ou justificativas adicionais.

// ================================================================ // ANOTAÇÕES DE TRABALHO // ================================================================ // TODO: revisar responsividade mobile // FIXME: ajustar timeout da API /login

// NO CHAT: // VÁ DIRETO AO PONTO, SEM ENROLAÇÃO // NÃO USE EMOJIS ATÉ NO CHAT // SEM EXPLICAÇÕES DESNECESSÁRIAS