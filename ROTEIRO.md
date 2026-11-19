# Sentinela: roteiro de construção

> Versão adaptada: o Sentinela **não usa IA**. A detecção é feita por regras (regex) escritas e entendidas pelo Carlos. Os evals continuam, agora medindo as regras.

## Por que esse projeto

Código novo entra rápido (escrito à mão ou gerado por IA), mas alguém precisa saber se ele é seguro. O Sentinela revisa o diff de cada pull request em busca de vulnerabilidades conhecidas, de forma determinística, gratuita e offline. O Carlos é quem entende, mede e melhora as regras.

Numa entrevista, ele mostra de uma vez:

- **Segurança:** OWASP Top 10, CWE, vulnerabilidades reais
- **Backend/CLI:** Python, testes, empacotamento
- **Engenharia de verdade:** evals (medir se as regras acertam), CI/CD
- **Produto:** usuários reais (devs open source usando a Action)

O diferencial são os **evals**. Quase ninguém em nível de estágio mostra que sabe medir a qualidade de uma ferramenta de segurança (precisão e recall).

## Preparação (feita)

Repositório, venv com Python 3.12, `.gitignore`, `CLAUDE.md`, `gh` autenticado. Não precisa de chave de API.

---

## Fase 1: esqueleto e leitura de diff (feita)

CLI com Typer, comando `revisar`, `diff.py` que quebra o diff por arquivo guardando nome, linhas adicionadas e número da linha. Testes com 3 diffs de exemplo.

**Carlos precisa saber explicar:** o que é um diff unificado, por que separar por arquivo, como o Typer transforma função em comando.

## Fase 2: regras de detecção (feita, falta o Carlos revisar)

`models.py` (Finding, Severity), `regras.py` (10 regras: SQL injection, XSS, segredo no código, path traversal, desserialização insegura, SSRF, injeção de comando, cripto fraca, TLS desativado) e `scanner.py`, que aplica cada regra às linhas adicionadas.

**Carlos precisa saber explicar:** como cada regex funciona, por que regras têm `excecao`, por que comentários são ignorados, o que uma regra por linha **não** consegue ver (de onde vem uma variável, código em várias linhas, falta de autorização).

## Fase 3: relatório (feita)

`report.py` com três formatos: terminal (Rich, colorido por severidade), markdown (para comentário de PR) e JSON. Flag `--formato`. O comando sai com código 1 se houver achado de severidade alta ou crítica.

**Carlos precisa saber explicar:** exit code e por que ele importa pro CI.

## Fase 4: evals, a parte mais importante (40 casos e baseline feitos; falta a iteração nas regras)

- `evals/casos/` com 30 casos rotulados em JSON: 20 vulneráveis (uma ou mais por categoria) e 10 seguros parecidos com os vulneráveis. Cada caso: `codigo`, `linguagem`, `vulneravel` (bool), `categoria_esperada`.
- `run_evals.py` roda o scanner em todos e mostra precisão, recall e uma tabela dos erros. Salva o resultado em `evals/resultados/` com data.
- **Sem ajuda de IA**, o Carlos escreve à mão mais 10 casos difíceis (código seguro que parece perigoso e vice-versa). Isso mostra critério próprio.
- Iterar nas regras, comparando os números antes e depois de cada mudança. Guardar cada versão dos resultados.

O recall vai expor as limitações das regras (ex.: `open(os.path.join("/uploads", nome))` com `nome` vindo de fora passa batido). Documentar isso é parte do valor.

**Carlos precisa saber explicar:** diferença entre precisão e recall, por que falso positivo irrita o usuário, o que ele mudou nas regras e quanto melhorou.

## Fase 5: GitHub Action (feita e validada num PR real)

`.github/workflows/sentinela.yml` roda o Sentinela em todo pull request, pega o diff contra a branch base e posta o relatório markdown como comentário. Documentar no README como outra pessoa instala a Action. Sem secrets de IA: só o `GITHUB_TOKEN` com permissão de comentar em PR.

**Carlos precisa saber explicar:** como o GitHub Actions funciona, o que são secrets, permissões do token.

## Fase 6: README e usuários reais (contínuo)

- README com GIF do terminal, tabela de resultados dos evals e decisões técnicas
- Seção "Limitações": o que o Sentinela não pega (isso conta pontos, mostra maturidade)
- Publicar e pedir pra 3 a 5 colegas da PUCRS usarem nos projetos deles
- Abrir 1 ou 2 issues reais a partir do feedback e resolver

---

## Extras se sobrar fôlego

- Análise de AST (módulo `ast`) para Python: enxerga o arquivo inteiro e rastreia variáveis, reduzindo falso positivo e pegando mais casos
- Arquivo de configuração (`.sentinela.toml`) para ligar/desligar regras e ignorar caminhos
- Comentário `# sentinela: ignore` para marcar falso positivo numa linha
- Mais linguagens (JavaScript/TypeScript) com regras próprias
- Formato SARIF, para aparecer na aba Security do GitHub

## Como apresentar na entrevista (2 minutos)

1. **Problema:** código novo entra rápido, mas ninguém revisa a segurança com o mesmo ritmo.
2. **Solução:** ferramenta que roda em todo PR, aponta a vulnerabilidade, a linha, o CWE e como corrigir, sem depender de serviço externo.
3. **Como sei que funciona:** 40 casos rotulados, precisão X%, recall Y%, melhorei Z pontos ajustando as regras.
4. **O que aprendi:** onde regex erra e por que medir importa.
5. **Limitações:** o que ele não pega e o que eu faria a seguir (AST).

## Regra de ouro

Se o Carlos não consegue explicar uma parte do código sem olhar, ele pede pro Claude Code explicar, reescreve com as palavras dele num comentário e só então segue. O projeto vale pelo que ele entende, não pelo que foi gerado.
