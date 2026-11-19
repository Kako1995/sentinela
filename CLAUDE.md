# Sentinela

Ferramenta de linha de comando que revisa diffs de código em busca de vulnerabilidades de segurança usando a API da Anthropic, e roda como GitHub Action em pull requests.

O objetivo do projeto é aprendizado e portfólio: o Carlos precisa entender e conseguir explicar cada parte. O diferencial são os **evals** (medir precisão e recall do revisor).

## Stack

- Python 3.10+ (alvo: 3.12)
- CLI: Typer
- Modelos e validação: Pydantic v2
- Saída no terminal: Rich
- IA: SDK `anthropic`
- Testes: pytest (a API da Anthropic é sempre mockada nos testes)
- Empacotamento: `pyproject.toml`, pacote `sentinela` em `src/sentinela/`

## Estrutura alvo

```
src/sentinela/
  cli.py        # comandos Typer (revisar)
  diff.py       # quebra diff unificado em trechos por arquivo
  models.py     # Finding, Severity (Pydantic)
  prompts.py    # prompt de sistema, versionado
  reviewer.py   # chamada à API + validação + retry
  report.py     # formatos terminal, markdown, json
tests/
evals/
  casos/        # casos rotulados em JSON
  resultados/   # saídas de cada rodada, com data
  run_evals.py
.github/workflows/sentinela.yml
```

## Formato do achado

```python
class Severity(str, Enum):
    baixa = "baixa"
    media = "media"
    alta = "alta"
    critica = "critica"

class Finding(BaseModel):
    arquivo: str
    linha: int            # linha no arquivo novo
    severidade: Severity
    categoria: str        # ex.: "SQL injection", "XSS", "segredo no código"
    cwe: str | None       # ex.: "CWE-89"
    explicacao: str       # em português, curta e específica
    correcao: str         # sugestão concreta
```

A resposta da IA deve ser JSON que valida contra uma lista de `Finding`. Se for inválida, tentar mais uma vez e depois registrar o erro sem derrubar a execução.

## Regras de código

- Código, nomes de módulos e funções em inglês onde já for convenção; mensagens para o usuário, explicações dos achados e docs em **português**.
- Funções pequenas e tipadas. Sem abstrações que ainda não são necessárias.
- Nunca chamar a API real em testes. Usar mock.
- Nunca commitar chave de API. A chave vem de `ANTHROPIC_API_KEY` (`.env` local, `secrets` no CI).
- O comando `revisar` sai com código 1 se houver achado de severidade alta ou crítica, 0 caso contrário.
- Ao mudar o prompt em `prompts.py`, guardar a versão anterior e rodar os evals para comparar.

## Comandos

```bash
source .venv/bin/activate
pip install -e ".[dev]"
pytest
sentinela revisar caminho/do.diff
git diff main | sentinela revisar -
python evals/run_evals.py
```

## Como trabalhar neste projeto

- Uma fase do `ROTEIRO.md` por vez. Não adiantar fases.
- Depois de cada parte, explicar em poucas linhas o que foi feito e por quê, para o Carlos conseguir reexplicar.
- Se algo for decisão de design (formato, nome, estrutura), propor e justificar antes de gerar muito código.
