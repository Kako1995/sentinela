# Sentinela

Revisor de segurança para diffs de código, baseado em regras (sem IA, sem rede). Lê um diff, aponta vulnerabilidades nas **linhas adicionadas** e diz o arquivo, a linha, o CWE e como corrigir. Roda no terminal e como GitHub Action em pull requests.

> Em construção: veja o `ROTEIRO.md`.

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

## Desenvolvimento

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
python evals/run_evals.py --rotulo minha-rodada   # mede precisão e recall (veja evals/README.md)
```
