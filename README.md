# Sentinela

Revisor de segurança para diffs de código, baseado em regras e em análise de árvore sintática de Python, JavaScript e TypeScript (sem IA, sem rede). Lê um diff, aponta vulnerabilidades nas **linhas adicionadas** e diz o arquivo, a linha, o CWE e como corrigir. Roda no terminal e como GitHub Action em pull requests.

> Projeto de estudo, em evolução. Os números abaixo são medidos, não estimados, e a seção [Limitações](#limitações) diz com franqueza o que ele **não** pega. Mais detalhes: [como foi medido](docs/evals.md) e [limitações completas](docs/limitacoes.md).

## Como é a saída

![Terminal mostrando o Sentinela revisando um diff: acha um segredo no código e um XSS, depois roda de novo com --nota](docs/demo.gif)

```
$ git diff main | sentinela revisar -

 ALTA  segredo no código  config.py:2 · CWE-798
  Um valor que parece segredo (chave, token ou senha) está escrito direto no
  código.
  Correção: Leia o valor de uma variável de ambiente ou de um gerenciador de
  segredos e revogue a chave exposta.

 MEDIA  XSS  web/views.py:22 · CWE-79
  HTML é montado ou inserido com valor variável sem escapar, abrindo espaço para
  script injetado.
  Correção: Escape a saída (ou use textContent / template com autoescape) em vez
  de concatenar HTML.

2 achado(s): 1 alta, 1 media.
```

No terminal a severidade vem colorida. Em pull requests, o mesmo relatório vira um comentário em markdown.

## O que ele detecta

Duas camadas, cada achado com CWE, severidade, explicação e correção em português:

1. **Regras por linha** (21 regras, qualquer linguagem): olham o texto de cada linha adicionada.
2. **Análise por AST** (Python, JavaScript e TypeScript): leem o arquivo inteiro pela árvore sintática (`ast` para Python, `tree-sitter` para JS/TS/TSX). Conseguem ligar a *origem* de um dado (`request.args`, `req.query`, `request.json()`, argumentos de server actions do Next.js, parâmetros de rota) ao seu *uso* (`open`, `fs.readFile`, `requests.get`, `fetch`, `query`), mesmo em linhas diferentes, ver SQL montado em várias linhas e olhar a rota ou a função inteira.

| Categoria | CWE | Severidade | Camada |
|---|---|---|---|
| Injeção de comando | CWE-78 | crítica | linha + AST de JS (`exec`/`execSync` com dado externo) |
| Desserialização insegura | CWE-502 | crítica | linha + AST de Python (`read_pickle`, `joblib.load`... com dado externo) |
| Segredo no código (formatos conhecidos) | CWE-798 | crítica | linha |
| SQL injection | CWE-89 | alta | linha + AST (em várias linhas, só se chega a um `execute`/`query`) |
| NoSQL injection (`$where` do MongoDB, que executa JavaScript no banco, com a expressão montada por concatenação, template, f-string ou `%`) | CWE-943 | média | linha |
| Path traversal | CWE-22 | alta | AST em Python/JS/TS, linha nas demais linguagens |
| SSRF | CWE-918 | alta | AST em Python/JS/TS, linha nas demais linguagens |
| Trava de SSRF frágil (`host.startsWith('127.')`, regex de prefixos privados): bloqueia endereços internos comparando o começo do texto | CWE-918 | média | linha |
| Segredo no código (atribuição, senha de 6+ caracteres com número ou símbolo, URL com senha) | CWE-798 | alta | linha |
| XSS (`dangerouslySetInnerHTML`, `.html()` do jQuery, HTML na resposta do Express, `bypassSecurityTrustHtml` e irmãos do Angular com valor que não é fixo) | CWE-79 | média | linha + AST de JS |
| Filtro em texto do Supabase/PostgREST (`.or()`) com dado do usuário | CWE-89 | média | AST de JS |
| Criptografia fraca (MD5/SHA-1, modo ECB, DES, `random`/`Math.random()` gerando token ou senha) | CWE-327, CWE-338 | média | linha (a de `random` olha 4 linhas) |
| Verificação TLS desativada | CWE-295 | média | linha |
| Exposição de rede (bind em `0.0.0.0`, não só localhost) | CWE-1327 | média | linha |
| Falta de autorização (rota PUT/DELETE/PATCH, route handler e server action sem autenticação visível) | CWE-862 | média | AST |
| Autenticação fraca: e-mail do cabeçalho do Cloudflare Access (`Cf-Access-Authenticated-User-Email`) usado como identidade em arquivo que não verifica o JWT | CWE-290 | média | linha + arquivo inteiro |

A AST só trata como "dado externo" o `request`/`req` de arquivos de aplicação web (que importam um framework ou declaram rotas), os parâmetros de rotas e os argumentos das funções exportadas de um arquivo `'use server'` do Next.js (que vêm do navegador). `input()` de um script de terminal não conta, e o `request` de uma biblioteca HTTP também não. Reconhece como limpeza `secure_filename`, `basename`, `Number()`, `encodeURIComponent`, `escapeHtml` e validações do tipo `if (!LISTA.includes(x)) return`, além de host fixo no começo de uma URL.

## Uso no terminal

**Requisito: Python 3.10 ou mais novo** (confira com `python3 --version`; o Python que vem de fábrica no macOS é o 3.9 e não serve, instale um mais novo, por exemplo com `brew install python@3.12`). Sem chave de API e sem rede.

```bash
pip install git+https://github.com/Kako1995/sentinela   # só para usar
# ou, clonando o repositório para mexer no código:
pip install -e ".[dev]"

sentinela revisar mudancas.diff
git diff main | sentinela revisar -
git diff main | sentinela revisar - --formato markdown
git diff main | sentinela revisar - --raiz .      # ativa a análise por AST nos .py/.js/.ts do diff
```

| Opção | O que faz |
|---|---|
| `--formato terminal` (padrão) | Relatório colorido por severidade |
| `--formato markdown` | Texto pronto para comentário de PR |
| `--formato json` | Só JSON, para usar em pipe |
| `--formato sarif` | [SARIF](https://sarifweb.azurewebsites.net/) 2.1.0, para o GitHub Code Scanning mostrar os achados na aba **Security** do repositório, não só no comentário do PR. Ignora `--nota` (SARIF é lido por ferramenta, não por gente) |
| `--raiz PASTA` | Lê os `.py`, `.js`, `.ts` e `.tsx` do diff por inteiro, a partir dessa pasta, e ativa a análise por AST. A Action já usa. Só lê arquivos dentro da pasta, sem seguir links simbólicos, e só se baterem com o diff |
| `--nota` | Acrescenta uma nota de 0 a 10 ao relatório (fórmula e aviso de limitação juntos — não é uma nota de segurança, ver abaixo) |

### Analisar um projeto inteiro

Para um software que já existe, em vez de um diff:

```bash
sentinela varrer caminho/do/projeto
sentinela varrer . -x docs -f markdown            # -x ignora caminhos (pode repetir)
sentinela varrer . --incluir-md                    # analisa também os .md/.mdx
sentinela varrer . --incluir-testes                # analisa também testes (tests/, *.spec.ts, test_*.py)
sentinela varrer . --incluir-traducoes             # analisa também os JSON/YAML de tradução (i18n/, locales/)
```

Ele lê todos os arquivos de texto (`.py`, `.js`, `.ts` e `.tsx` também passam pela análise por AST), pulando dependências e builds (`node_modules`, `.venv`, `vendor`, `.next`, `_next`...), caches, arquivos minificados (`*.min.js`), SVG, binários, links simbólicos e arquivos com mais de 1 MB. **Markdown (`.md`/`.mdx`), testes (`tests/`, `*.spec.ts`, `*.test.js`, `test_*.py`) e arquivos de dados de tradução (JSON/YAML/`.po` em `i18n/`, `locales/`...) também ficam de fora** por padrão: têm HTML, credenciais e código vulnerável de exemplo de propósito e geravam alertas que não são do código. Num projeto real em Angular, testes e traduções somavam **281 dos 342 alertas (82%)**, e um texto em tailandês ou japonês, que não tem espaços, chegava a ser tomado por uma senha. Use `--incluir-md`, `--incluir-testes` ou `--incluir-traducoes` para analisar mesmo assim; código dentro de `i18n/` (como `i18n/index.ts`) continua sendo analisado, e apontar o `varrer` para uma pasta chamada `tests` a lê. **Ele sempre diz o que pulou e por quê** (na saída de erro, então `-f json` continua sendo só o relatório): por motivo, com os nomes dos primeiros arquivos, e as linhas longas demais (acima de 2000 caracteres) com o arquivo em que estão. Assim, "nenhum alerta" nunca esconde um arquivo que nem foi lido. Os mesmos formatos e códigos de saída do `revisar` valem aqui. Em projeto inteiro os falsos positivos se acumulam, então trate o resultado como uma **lista para conferir**, não como veredito. Só analise código seu ou que você tem permissão de analisar.

**Código de saída:** `1` se houver achado de severidade **alta ou crítica**, `0` caso contrário, `2` se o arquivo não existir. É isso que faz o CI falhar.

### A nota (`--nota`)

Uma régua rápida de 0 a 10, só se você pedir com `--nota` (em `revisar` ou `varrer`). A fórmula é simples de propósito, pra caber numa frase: começa em 10; cada achado crítico tira 3 pontos, alta tira 2, média tira 1, baixa tira 0,5; nunca passa de 0 nem de 10.

**Não é uma nota de segurança.** Uma nota alta quer dizer só que as regras e a análise por AST não acharam muita coisa nas linhas analisadas — não que o código é seguro. Por isso ela sempre vem junto com esse aviso, em qualquer formato de saída.

### Configurar (`.sentinela.toml`)

Arquivo opcional, na raiz do projeto (a pasta passada em `varrer` ou em `--raiz`):

```toml
[regras]
desativar = ["segredo-url-com-senha", "tls-sem-verificacao"]

[varrer]
ignorar = ["migrations/", "*.generated.ts"]
```

Sem o arquivo, ou com algum problema nele (sintaxe inválida, campo no formato errado), o Sentinela roda do jeito de sempre — nada fica desativado — e avisa o motivo no terminal. O próprio arquivo `.sentinela.toml` não entra na varredura.

Pra silenciar só **uma linha** (em vez da regra inteira no projeto), um comentário nela mesma, igual `# noqa` ou `// eslint-disable-line`:

```python
h = hashlib.md5(dados)  # sentinela: ignore (usado só como chave de cache, não senha)
```

## Instalar a Action em outro repositório

Crie `.github/workflows/sentinela.yml` no repositório que você quer proteger:

```yaml
name: Sentinela
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write  # para comentar o relatório no PR

jobs:
  revisar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # o Sentinela precisa do commit base para calcular o diff

      - uses: Kako1995/sentinela@v0.3.0   # fixe uma versão; @main é a mais nova, sem garantia de estabilidade
        with:
          excluir: "tests docs"  # opcional: caminhos a ignorar, separados por espaço
```

Pronto. Em cada pull request o Sentinela:

1. calcula o diff entre a base e o PR;
2. posta (e depois **atualiza**, sem duplicar) um comentário com o relatório;
3. falha o check se achar algo de severidade alta ou crítica.

Não precisa de nenhuma chave de API nem de `secrets`: ele usa só o `GITHUB_TOKEN` que o próprio GitHub dá a cada execução.

**Permissões:** `contents: read` deixa o job ler o código. `pull-requests: write` é o que permite comentar no PR. Nada além disso.

**Pontos de atenção**
- O `fetch-depth: 0` é obrigatório. Com o checkout raso padrão o commit base não existe e o Sentinela falha de propósito, em vez de passar sem revisar.
- PRs vindos de **forks** recebem um token somente leitura: o comentário não é postado, mas o relatório aparece no resumo do job e o check continua funcionando.
- **Fixe uma versão** (`@v0.3.0`) em vez de `@main` se quiser estabilidade: `@main` muda a cada PR mesclado. As versões estão em [Releases](https://github.com/Kako1995/sentinela/releases).

**Opcional: aparecer na aba Security.** A Action acima só comenta no PR. Para também mandar os achados pro GitHub Code Scanning (pede a permissão extra `security-events: write`, por isso fica fora do padrão):

```yaml
      - run: pip install git+https://github.com/Kako1995/sentinela
      - run: git diff ${{ github.event.pull_request.base.sha }} | sentinela revisar - -f sarif > sentinela.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sentinela.sarif
```

## Como sei que funciona: os evals

Rodo o scanner em casos de código rotulados à mão (vulnerável ou seguro) e meço:

- **Precisão:** dos alertas que ele deu, quantos eram reais. Baixa precisão = falso positivo, e falso positivo faz as pessoas ignorarem a ferramenta.
- **Recall:** das vulnerabilidades que existem, quantas ele achou.

**Hoje: 330 casos, precisão 99% e recall 97%** (158 vulneráveis, dos quais 153 achados e 5 perdidos; 172 seguros, dos quais 171 passaram e 1 deu falso positivo).

| Categoria | Achados | Recall |
|---|---:|---:|
| SQL injection | 16/16 | 100% |
| NoSQL injection | 10/10 | 100% |
| SSRF | 26/27 | 96% |
| XSS | 25/25 | 100% |
| Criptografia fraca | 12/12 | 100% |
| Autenticação fraca | 7/7 | 100% |
| Injeção de comando | 7/7 | 100% |
| Exposição de rede | 4/4 | 100% |
| Segredo no código | 17/18 | 94% |
| Path traversal | 15/16 | 94% |
| Falta de autorização | 11/12 | 92% |
| Desserialização insegura | 3/4 | 75% |

**Como ler esses números com cuidado**

- **Quase todos os casos foram escritos pelo mesmo autor (eu, com IA) que escreveu as regras.** Casos escritos por outra pessoa, sem olhar as regras, seriam o teste mais forte, e ainda faltam.
- **O ganho é, em parte, ajuste ao teste.** A tentativa de manter alguma honestidade foi escrever cada conjunto de casos *antes* de implementar o que ele mede e guardar a medição de cada versão em [`evals/resultados/`](evals/resultados/). Mesmo assim, os conjuntos não são independentes entre si.
- **A validação que mais pesou foi rodar em código real.** A primeira varredura em 7 repositórios reais de terceiros deu **zero acertos entre os alertas de severidade alta e crítica** (na minha leitura de cada um): foi o que mostrou que os números dos evals eram otimistas, e levou à maior parte das correções. Várias correções foram revalidadas varrendo de novo esses repositórios e 1685 arquivos de bibliotecas Python reais.
- **Em código de projetos públicos a precisão é menor do que nos evals.** Num teste em 5 projetos públicos de JS/TS, os alertas de severidade alta e crítica dos apps "normais" eram válidos em só 2 de 11, e o Sentinela deixou passar cerca de 10 falhas conhecidas do Juice Shop (o `bypassSecurityTrustHtml` do Angular e o `$where` do MongoDB já foram corrigidos; o **redirecionamento aberto continua sem ser detectado**, por decisão: veja [`docs/limitacoes.md`](docs/limitacoes.md)) e a SSRF do NodeGoat, por estar num arquivo que só exporta o handler `(req, res)`. O que já foi corrigido e o que falta está em [`docs/evals.md`](docs/evals.md).
- **Nenhum acerto anterior se perde sem aparecer:** um CI roda os evals em todo PR e compara cada caso com [`evals/baseline.json`](evals/baseline.json) (veja [Desenvolvimento](#desenvolvimento)).

O histórico completo, rodada a rodada, com o que cada correção mudou e os erros meus que o processo pegou, está em **[`docs/evals.md`](docs/evals.md)**. Os casos e o método estão em [`evals/`](evals/README.md).

## Limitações

O que o Sentinela **não** pega, e por quê (a lista completa, com cada regra e seu ponto cego, está em [`docs/limitacoes.md`](docs/limitacoes.md)):

- **Só Python, JavaScript e TypeScript têm análise por AST.** Java, PHP, Go e o resto contam apenas com as regras por linha.
- **A análise por AST é por função, com uma exceção.** Em Python, uma função solta chamada direto (`ajuda(x)`, não `obj.ajuda(x)`) **no mesmo arquivo** já é seguida: se a rota repassa o dado para essa função ajudante, a AST sabe. Isso ainda não vale para JS/TS, nem para chamada **entre arquivos** (`import`) em nenhuma das duas linguagens: se a rota passa o dado para um auxiliar em outro módulo que abre o arquivo, a ligação se perde. Em funções que não são rotas (nem server actions) e não são chamadas por uma, parâmetros não contam como dado externo (um `pd.read_pickle(arquivo_enviado)` num auxiliar isolado passa batido), e uma server action fina que repassa tudo a outra função em outro arquivo gera um aviso de autorização que pode ser falso.
- **Regras por linha só veem uma linha** (fora a regra do `dangerouslySetInnerHTML`, que olha até 60, e a de `random` para segredo, que olha 4). Em JavaScript e nas demais linguagens, um valor que vem da requisição numa linha e é usado na seguinte perde a ligação.
- **Sem tipos.** Um valor validado por `zod` continua contando como externo; `String(x)` e outras conversões não limpam nada.
- **Acertar pelo motivo errado.** Os evals medem se o alerta saiu, não se foi pelo motivo certo.
- Só analisa as **linhas adicionadas** (em modo diff): não vê vulnerabilidades que já estavam no arquivo. Para isso existe o `varrer`.
- **As regras mais novas são heurísticas, e cada uma tem um ponto cego documentado:** `random` para gerar segredo, senha curta, token de jogo, `innerHTML` só com número, trava de SSRF por prefixo e Cloudflare Access sem JWT. Elas foram desenhadas para errar pelo lado de alertar menos, e a lista do que passa está em [`docs/limitacoes.md`](docs/limitacoes.md).

Em resumo: é uma rede de segurança rápida para padrões conhecidos, não uma auditoria. Não substitui revisão humana nem ferramentas de análise mais completas (como CodeQL ou Semgrep).

## Decisões técnicas

- **Regras e AST em vez de IA.** É determinístico, gratuito, offline e cada alerta é explicável: dá para apontar a regra exata que disparou. As regras por linha funcionam em qualquer linguagem; a AST dá a precisão que o texto de uma linha não dá. Python usa o módulo `ast` da biblioteca padrão. **Para JS/TS foi preciso adicionar uma dependência**: o `tree-sitter` (com as gramáticas de JavaScript e TypeScript), porque a biblioteca padrão não traz parser de JS e escrever um à mão seria frágil. Ele vem em binários prontos (Linux, macOS, Windows) e funciona offline. Sem ele instalado, só as regras por linha e a AST de Python funcionam.
- **A AST substitui as regras de path traversal e SSRF nos arquivos Python/JS/TS que ela consegue ler**, porque sabe de onde vem o dado, e as regras por linha só viam a palavra `request` na mesma linha. Se o arquivo não parseia, as regras por linha voltam a valer.
- **Ler o arquivo do disco com cuidado.** O nome do arquivo vem do diff, que pode ser de um PR malicioso. Por isso o `--raiz` só lê arquivos dentro da pasta indicada, não segue links simbólicos e descarta o arquivo se ele não bater linha a linha com o diff.
- **Limite de tamanho por linha, por segurança, não só desempenho.** Algumas regex (ex.: SQL injection) têm custo que cresce com o quadrado do tamanho da linha quando ela não casa. Uma linha gigante sem quebra de verdade (SVG, bundle minificado) — e o conteúdo do arquivo também pode vir de um diff malicioso — travava a varredura por minutos. Linha acima de 2000 caracteres pula as regras por linha; a AST, que lê o arquivo de outro jeito, não é afetada.
- **"Dado externo" só em contexto web.** `request`/`req` conta se o arquivo importa um framework web ou declara rotas; `input()` de script nunca conta. Foi a lição da varredura de bibliotecas reais. No Next.js, os argumentos das funções exportadas de um arquivo `'use server'` contam como externos, porque vêm do navegador, e os parâmetros dos route handlers (`route.ts`) e das páginas (`page.tsx`) vêm da URL.
- **Revisar o diff, não o repositório.** O desenvolvedor só vê alertas sobre o que acabou de escrever, e o tempo de execução não cresce com o tamanho do projeto.
- **Falhar em vez de aprovar sem revisar.** Se o git não consegue calcular o diff (checkout raso), a Action falha com uma mensagem clara. Um diff vazio por erro viraria "nenhum problema", que é pior que um erro.
- **Código de saída por severidade.** Só alta e crítica quebram o CI. Média e baixa aparecem no relatório sem bloquear, para a ferramenta não virar um obstáculo.
- **Dois níveis de silenciar um alarme falso, não um só.** `# sentinela: ignore` numa linha é exceção pontual, de quem está mexendo naquele código agora; `.sentinela.toml` desativa a regra pro projeto inteiro, decisão de quem mantém o repositório. Sem os dois, alguém de fora usando a ferramenta e batendo num alarme falso não teria opção além de reclamar ou ignorar o relatório inteiro.
- **Evals por caso, com casos difíceis separados.** Medir só em exemplos fáceis daria números bonitos e inúteis, por isso os casos que enganam a regra têm uma tabela própria.
- **Um comentário por PR, atualizado a cada push**, achado por um marcador invisível, em vez de uma pilha de comentários.

## Desenvolvimento

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
python evals/run_evals.py --rotulo minha-rodada   # mede precisão e recall (veja evals/README.md)
python evals/run_evals.py --verificar             # a trava de regressão do CI, rodando na sua máquina
```

**CI (`.github/workflows/testes.yml`).** Todo pull request e todo push na `main` rodam o `pytest` (em Python 3.10 e 3.12) e os evals com uma **trava de regressão**: cada um dos casos é comparado com o veredito que tinha em `evals/baseline.json`, e **um acerto que vira erro, ou um caso que some, reprova o PR**. Casos novos e melhorias também pedem para atualizar a baseline (`python evals/run_evals.py --atualizar-baseline`), de modo que o diff dela mostre, caso a caso, o que a mudança fez com as métricas. É a regra "nenhum acerto anterior pode se perder", que antes dependia de eu lembrar de conferir, agora automática.

Estrutura: `src/sentinela/` (`diff.py` lê o diff, `varredura.py` percorre pastas, `regras.py` define as regras por linha, `ast_python.py` e `ast_js.py` fazem a análise por AST, `scanner.py` junta tudo, `report.py` formata a saída, `avaliacao.py` calcula as métricas), `tests/`, `evals/` e `action.yml`.

## Licença

[MIT](LICENSE).
