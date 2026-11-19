# Sentinela

Revisor de segurança para diffs de código, baseado em regras e em análise de árvore sintática de Python, JavaScript e TypeScript (sem IA, sem rede). Lê um diff, aponta vulnerabilidades nas **linhas adicionadas** e diz o arquivo, a linha, o CWE e como corrigir. Roda no terminal e como GitHub Action em pull requests.

> Projeto de estudo, em evolução. Os números abaixo são medidos, não estimados, e a seção [Limitações](#limitações) diz com franqueza o que ele **não** pega.

## Como é a saída

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

1. **Regras por linha** (13 regras, qualquer linguagem): olham o texto de cada linha adicionada.
2. **Análise por AST** (Python, JavaScript e TypeScript): leem o arquivo inteiro pela árvore sintática (`ast` para Python, `tree-sitter` para JS/TS/TSX). Conseguem ligar a *origem* de um dado (`request.args`, `req.query`, `request.json()`, argumentos de server actions do Next.js, parâmetros de rota) ao seu *uso* (`open`, `fs.readFile`, `requests.get`, `fetch`, `query`), mesmo em linhas diferentes, ver SQL montado em várias linhas e olhar a rota ou a função inteira.

| Categoria | CWE | Severidade | Camada |
|---|---|---|---|
| Injeção de comando | CWE-78 | crítica | linha + AST de JS (`exec`/`execSync` com dado externo) |
| Desserialização insegura | CWE-502 | crítica | linha + AST de Python (`read_pickle`, `joblib.load`... com dado externo) |
| Segredo no código (formatos conhecidos) | CWE-798 | crítica | linha |
| SQL injection | CWE-89 | alta | linha + AST (em várias linhas, só se chega a um `execute`/`query`) |
| Path traversal | CWE-22 | alta | AST em Python/JS/TS, linha nas demais linguagens |
| SSRF | CWE-918 | alta | AST em Python/JS/TS, linha nas demais linguagens |
| Segredo no código (atribuição, URL com senha) | CWE-798 | alta | linha |
| XSS (`dangerouslySetInnerHTML`, `.html()` do jQuery, HTML na resposta do Express) | CWE-79 | média | linha + AST de JS |
| Filtro em texto do Supabase/PostgREST (`.or()`) com dado do usuário | CWE-89 | média | AST de JS |
| Criptografia fraca (MD5/SHA-1) | CWE-327 | média | linha |
| Verificação TLS desativada | CWE-295 | média | linha |
| Falta de autorização (rota PUT/DELETE/PATCH, route handler e server action sem autenticação visível) | CWE-862 | média | AST |

A AST só trata como "dado externo" o `request`/`req` de arquivos de aplicação web (que importam um framework ou declaram rotas), os parâmetros de rotas e os argumentos das funções exportadas de um arquivo `'use server'` do Next.js (que vêm do navegador). `input()` de um script de terminal não conta, e o `request` de uma biblioteca HTTP também não. Reconhece como limpeza `secure_filename`, `basename`, `Number()`, `encodeURIComponent`, `escapeHtml` e validações do tipo `if (!LISTA.includes(x)) return`, além de host fixo no começo de uma URL.

## Uso no terminal

```bash
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
| `--raiz PASTA` | Lê os `.py`, `.js`, `.ts` e `.tsx` do diff por inteiro, a partir dessa pasta, e ativa a análise por AST. A Action já usa. Só lê arquivos dentro da pasta, sem seguir links simbólicos, e só se baterem com o diff |

### Analisar um projeto inteiro

Para um software que já existe, em vez de um diff:

```bash
sentinela varrer caminho/do/projeto
sentinela varrer . -x tests -x docs -f markdown   # -x ignora caminhos (pode repetir)
```

Ele lê todos os arquivos de texto (`.py`, `.js`, `.ts` e `.tsx` também passam pela análise por AST), pulando dependências (`node_modules`, `.venv`, `vendor`...), caches, binários, links simbólicos e arquivos com mais de 1 MB. Os mesmos formatos e códigos de saída do `revisar` valem aqui. Em projeto inteiro os falsos positivos se acumulam, então trate o resultado como uma **lista para conferir**, não como veredito. Só analise código seu ou que você tem permissão de analisar.

**Código de saída:** `1` se houver achado de severidade **alta ou crítica**, `0` caso contrário, `2` se o arquivo não existir. É isso que faz o CI falhar.

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

      - uses: Kako1995/sentinela@main
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
- Para outras pessoas usarem `Kako1995/sentinela@main`, o repositório precisa ser **público**.
- Fixe uma versão (`@v1`, quando houver) em vez de `@main` se quiser estabilidade.

## Como sei que funciona: os evals

Rodar o scanner em casos de código rotulados à mão (vulnerável ou seguro) e medir:

- **Precisão:** dos alertas que ele deu, quantos eram reais. Baixa precisão = falso positivo, e falso positivo faz as pessoas ignorarem a ferramenta.
- **Recall:** das vulnerabilidades que existem, quantas ele achou.

Quatro versões do scanner: `v1` (regras por linha), `v2` (exceções gerais contra falsos positivos), `v3` (análise por AST de Python) e `v4` (análise por AST de JavaScript/TypeScript). Nos mesmos 125 casos, `v3` → `v4`:

| Conjunto | Casos | Precisão | Recall |
|---|---|---|---|
| Python e gerais (iniciais, difíceis, validação, AST) | 92 | 98% → 98% | 92% → 92% |
| JavaScript/TypeScript (Express, Next.js, Supabase) | 33 | 20% → 100% | 7% → 100% |
| **Todos** | **125** | **90% → 98%** | **73% → 94%** |

Casos escritos só depois (medidos só na `v4`): um segundo conjunto de **17 casos de JS/TS** (precisão e recall de 88% na primeira medição, 100% depois de duas correções gerais) e 6 casos de regressão. Somando os **148 casos: precisão 99%, recall 95%** (1 falso positivo e 4 falsos negativos).

Recall por categoria (v4): SQL injection 100%, SSRF 100%, XSS 100%, injeção de comando 100%, falta de autorização 92%, path traversal 93%, segredo no código 80%, desserialização 75%.

**Como ler esses números com cuidado**
- **O ganho é, em parte, ajuste ao teste.** Escrevi a AST conhecendo os casos, e depois corrigi o que o segundo conjunto errou. Por isso as três rodadas seguintes de casos não são independentes entre si. A tentativa de manter alguma honestidade foi escrever cada conjunto *antes* de implementar o que ele mede e guardar as medições de cada versão em `evals/resultados/`.
- **Quase todos os casos foram escritos pelo mesmo autor (eu, com IA) que escreveu as regras.** Casos escritos por outra pessoa, sem olhar as regras, seriam o teste mais forte, e ainda faltam.
- **Evidência independente 3, o projeto TypeScript real da varredura anterior** (Next.js + Supabase) com a análise de JS/TS: 20 alertas na primeira versão, dos quais 15 eram falsos positivos sistemáticos de server actions (helpers `requireMaster()`, `requireNutriClinic()` não eram reconhecidos como autenticação). Depois de corrigir o padrão `require`/`assert`/`ensure` para 5 alertas: os 2 de segredo de antes e 3 server actions finas que repassam os dados a outra função (a autenticação pode estar lá, e a análise não segue chamadas entre arquivos). Nenhum alerta de path traversal, SSRF, SQL ou comando.
- **Evidência independente 1, projeto real de terceiros** (Next.js + Supabase, cerca de 500 arquivos): os alertas caíram de 15 para 2 com a v2, e os 13 que sumiram eram falsos positivos. Os 2 que sobraram são pontos para conferir; não há como medir o recall ali.
- **Evidência independente 2, 1650 arquivos de bibliotecas Python reais** (pydantic, pytest, pip, rich...): a varredura expôs defeitos sistemáticos que nenhum caso meu mostrava (o formato `<Classe ...>` de `__repr__` lido como HTML, `model.eval()` do PyTorch lido como `eval`, `request` de biblioteca lido como dado web). Depois de corrigi-los, os alertas caíram de 128 para 50. Os 50 restantes são, na maioria, usos legítimos de APIs sensíveis para um humano conferir (`eval`, `pickle.loads`, HTML montado por f-string), e **não houve nenhum alerta de AST**, que é o esperado para código que não é de aplicação web.
- Com 92 casos, cada caso vale cerca de 1 ponto percentual: os números mostram a tendência, não um valor exato.
- Duas vezes os evals pegaram um erro meu: a primeira correção de SQL derrubou o recall de SQL injection de 83% para 33% (um `(?i)` fazia `nome` parecer constante), e a primeira versão da AST tinha 3 classes de falso positivo que o conjunto fresco mostrou.

Os casos e o método estão em [`evals/`](evals/README.md), e cada rodada fica salva em `evals/resultados/`.

## Limitações

O que o Sentinela **não** pega, e por quê:

- **Só Python, JavaScript e TypeScript têm análise por AST.** Java, PHP, Go e o resto contam apenas com as regras por linha.
- **A análise por AST é por função.** Ela segue o dado dentro de uma função, mas não entre funções nem entre arquivos: se a rota passa o dado para um auxiliar em outro módulo que abre o arquivo, a ligação se perde. Em funções que não são rotas (nem server actions), parâmetros não contam como dado externo (um `pd.read_pickle(arquivo_enviado)` num auxiliar passa batido), e uma server action fina que repassa tudo a outra função gera um aviso de autorização que pode ser falso.
- **Falta de autorização é uma heurística.** Ela avisa (severidade média, que não derruba o CI) quando uma rota PUT/DELETE/PATCH, um route handler do Next.js ou uma server action com nome de verbo que altera dados (`apagar`, `update`, `criar`...) não mostra autenticação, mas autenticação feita num middleware, RLS ou gateway não é vista (só se reconhece pelo nome: `auth`, `session`, `getUser`, `requireX()`, `createClient`...): é um ponto para conferir, não um achado confirmado. Rotas POST não entram, porque costumam ser públicas (login, cadastro). Um IDOR (ler o recurso de outro usuário por id numa rota GET) não é detectado.
- **Regras por linha só veem uma linha** (fora a regra do `dangerouslySetInnerHTML`, que olha até 60). Em JavaScript e nas demais linguagens, um valor que vem da requisição numa linha e é usado na seguinte perde a ligação.
- **Sem tipos.** Um valor validado por `zod` continua contando como externo; `String(x)` e outras conversões não limpam nada.
- **Nomes e APIs que a regra não conhece.** Uma chave com o nome `chavePagamento` não é vista como segredo (a palavra "chave" também é "chave primária"), e o `startswith` mal feito para limitar uma pasta não é reconhecido como proteção quebrada.
- **Validação que a regra não entende** (falso positivo). Concatenar uma coluna já validada contra uma lista de permitidas continua disparando alerta em SQL, mesmo sendo seguro (a AST entende a validação por lista para caminhos e URLs, não para essa regra por linha). Comandos fixos com `shell=True`, `usedforsecurity=False`, `innerHTML` com texto fixo e referências a variáveis de ambiente já são tratados.
- **As exceções podem esconder um achado real.** Valores com palavras como `fake`, `exemplo` ou `sua-` são tratados como placeholder, e uma constante em MAIÚSCULAS concatenada ao SQL é tratada como constante do código.
- **A janela de 60 linhas** do `dangerouslySetInnerHTML`: um template literal maior que isso, com `${...}` perto do fim, não é visto.
- **Acertar pelo motivo errado.** Os evals medem se o alerta saiu, não se foi pelo motivo certo.
- Só analisa as **linhas adicionadas** (em modo diff): não vê vulnerabilidades que já estavam no arquivo. Para isso existe o `varrer`.

Em resumo: é uma rede de segurança rápida para padrões conhecidos, não uma auditoria. Não substitui revisão humana nem ferramentas de análise mais completas (como CodeQL ou Semgrep).

## Decisões técnicas

- **Regras e AST em vez de IA.** É determinístico, gratuito, offline e cada alerta é explicável: dá para apontar a regra exata que disparou. As regras por linha funcionam em qualquer linguagem; a AST dá a precisão que o texto de uma linha não dá. Python usa o módulo `ast` da biblioteca padrão. **Para JS/TS foi preciso adicionar uma dependência**: o `tree-sitter` (com as gramáticas de JavaScript e TypeScript), porque a biblioteca padrão não traz parser de JS e escrever um à mão seria frágil. Ele vem em binários prontos (Linux, macOS, Windows) e funciona offline. Sem ele instalado, só as regras por linha e a AST de Python funcionam.
- **A AST substitui as regras de path traversal e SSRF nos arquivos Python/JS/TS que ela consegue ler**, porque sabe de onde vem o dado, e as regras por linha só viam a palavra `request` na mesma linha. Se o arquivo não parseia, as regras por linha voltam a valer.
- **Ler o arquivo do disco com cuidado.** O nome do arquivo vem do diff, que pode ser de um PR malicioso. Por isso o `--raiz` só lê arquivos dentro da pasta indicada, não segue links simbólicos e descarta o arquivo se ele não bater linha a linha com o diff.
- **"Dado externo" só em contexto web.** `request`/`req` conta se o arquivo importa um framework web ou declara rotas; `input()` de script nunca conta. Foi a lição da varredura de bibliotecas reais. No Next.js, os argumentos das funções exportadas de um arquivo `'use server'` contam como externos, porque vêm do navegador, e os parâmetros dos route handlers (`route.ts`) e das páginas (`page.tsx`) vêm da URL.
- **Revisar o diff, não o repositório.** O desenvolvedor só vê alertas sobre o que acabou de escrever, e o tempo de execução não cresce com o tamanho do projeto.
- **Falhar em vez de aprovar sem revisar.** Se o git não consegue calcular o diff (checkout raso), a Action falha com uma mensagem clara. Um diff vazio por erro viraria "nenhum problema", que é pior que um erro.
- **Código de saída por severidade.** Só alta e crítica quebram o CI. Média e baixa aparecem no relatório sem bloquear, para a ferramenta não virar um obstáculo.
- **Evals por caso, com casos difíceis separados.** Medir só em exemplos fáceis daria números bonitos e inúteis, por isso os casos que enganam a regra têm uma tabela própria.
- **Um comentário por PR, atualizado a cada push**, achado por um marcador invisível, em vez de uma pilha de comentários.

## Desenvolvimento

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
python evals/run_evals.py --rotulo minha-rodada   # mede precisão e recall (veja evals/README.md)
```

Estrutura: `src/sentinela/` (`diff.py` lê o diff, `varredura.py` percorre pastas, `regras.py` define as regras por linha, `ast_python.py` e `ast_js.py` fazem a análise por AST, `scanner.py` junta tudo, `report.py` formata a saída, `avaliacao.py` calcula as métricas), `tests/`, `evals/` e `action.yml`.
