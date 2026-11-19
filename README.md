# Sentinela

Revisor de segurança para diffs de código, baseado em regras (sem IA, sem rede). Lê um diff, aponta vulnerabilidades nas **linhas adicionadas** e diz o arquivo, a linha, o CWE e como corrigir. Roda no terminal e como GitHub Action em pull requests.

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

10 regras, cada uma com CWE, severidade, explicação e correção em português:

| Categoria | CWE | Severidade |
|---|---|---|
| Injeção de comando | CWE-78 | crítica |
| Desserialização insegura | CWE-502 | crítica |
| Segredo no código (formatos conhecidos) | CWE-798 | crítica |
| SQL injection | CWE-89 | alta |
| Path traversal | CWE-22 | alta |
| SSRF | CWE-918 | alta |
| Segredo no código (atribuição) | CWE-798 | alta |
| XSS | CWE-79 | média |
| Criptografia fraca (MD5/SHA-1) | CWE-327 | média |
| Verificação TLS desativada | CWE-295 | média |

## Uso no terminal

```bash
pip install -e ".[dev]"

sentinela revisar mudancas.diff
git diff main | sentinela revisar -
git diff main | sentinela revisar - --formato markdown
```

| Opção | O que faz |
|---|---|
| `--formato terminal` (padrão) | Relatório colorido por severidade |
| `--formato markdown` | Texto pronto para comentário de PR |
| `--formato json` | Só JSON, para usar em pipe |

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

Medição atual (`v1-com-dificeis`, 40 casos):

| Conjunto | Casos | Precisão | Recall |
|---|---|---|---|
| Casos iniciais (20 vulneráveis, 10 seguros parecidos) | 30 | 86% | 60% |
| Casos difíceis (5 vulneráveis que parecem inofensivos, 5 seguros que parecem perigosos) | 10 | 43% | 60% |
| **Todos** | **40** | **71%** | **60%** |

Recall por categoria: injeção de comando 100%, SQL injection 80%, XSS 75%, desserialização 67%, SSRF 50%, segredo no código 50%, path traversal 33%, falta de autorização 0%.

Com 40 casos, cada caso vale 2,5 pontos percentuais: os números mostram a tendência, não um valor exato. Os casos e o método estão em [`evals/`](evals/README.md), e cada rodada fica salva em `evals/resultados/`.

## Limitações

O que o Sentinela **não** pega, e por quê:

- **Falta de autorização / controle de acesso** (recall 0%). O problema é uma verificação que *não existe*, e uma regra que olha o texto de uma linha não enxerga o que está ausente.
- **Origem dos dados.** Cada regra olha uma linha. Se um valor vem da requisição numa linha e é usado na seguinte (`url = request.json["x"]` e depois `requests.post(url)`), a ligação se perde.
- **Código em várias linhas.** Uma consulta SQL quebrada em duas linhas, com a interpolação na segunda, passa batido.
- **APIs que a regra não conhece.** `pd.read_pickle`, `.html()` do jQuery, nomes de variável como `chavePagamento`: o que não está na lista não é detectado.
- **Segredo dentro de uma URL** (`postgresql://usuario:senha@host`).
- **Validação correta que a regra não entende** (falso positivo). Concatenar uma coluna já validada contra uma lista de permitidas, usar `shell=True` com um comando fixo, `md5(..., usedforsecurity=False)` ou `innerHTML` com HTML fixo disparam alerta mesmo sendo seguros.
- **Acertar pelo motivo errado.** Os evals medem se o alerta saiu, não se foi pelo motivo certo.
- Só analisa as **linhas adicionadas**: não vê vulnerabilidades que já estavam no arquivo, nem como uma mudança afeta código existente.

Em resumo: é uma rede de segurança rápida para padrões conhecidos, não uma auditoria. Não substitui revisão humana nem ferramentas de análise mais completas (como CodeQL ou Semgrep).

## Decisões técnicas

- **Regras (regex) em vez de IA ou análise de árvore sintática.** É determinístico, gratuito, offline e cada alerta é explicável: dá para apontar a regra exata que disparou. O custo é o recall e a precisão acima; o próximo passo natural é usar o módulo `ast` do Python para ver o arquivo inteiro.
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

Estrutura: `src/sentinela/` (`diff.py` lê o diff, `regras.py` define as regras, `scanner.py` as aplica, `report.py` formata a saída, `avaliacao.py` calcula as métricas), `tests/`, `evals/` e `action.yml`.
