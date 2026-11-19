# Sentinela

Ferramenta de linha de comando que revisa diffs de código em busca de vulnerabilidades de segurança **usando regras (regex)**, e roda como GitHub Action em pull requests.

**Sem IA e sem chamadas de rede.** Decisão do Carlos: a detecção é determinística, gratuita e offline. Não adicionar dependência de LLM nem chave de API.

O objetivo do projeto é aprendizado e portfólio: o Carlos precisa entender e conseguir explicar cada parte. O diferencial são os **evals** (medir precisão e recall das regras).

## Stack

- Python 3.10+ (alvo: 3.12)
- CLI: Typer
- Modelos: Pydantic v2
- Saída no terminal: Rich
- Testes: pytest
- Empacotamento: `pyproject.toml`, pacote `sentinela` em `src/sentinela/`

## Estrutura

```
src/sentinela/
  cli.py        # comandos Typer (revisar, varrer)
  diff.py       # quebra diff unificado em trechos por arquivo
  varredura.py  # percorre uma pasta e trata cada arquivo como trecho (comando varrer)
  models.py     # Finding, Severity (Pydantic)
  regras.py     # lista de regras: regex por categoria de vulnerabilidade
  scanner.py    # aplica as regras às linhas adicionadas
  avaliacao.py  # lógica dos evals: casos, veredito, precisão e recall
  report.py     # (Fase 3) formatos terminal, markdown, json
tests/
evals/
  casos/        # um JSON por caso rotulado (ver evals/README.md)
  resultados/   # saídas de cada rodada, com data
  run_evals.py  # roda os casos e salva o resultado
.github/workflows/sentinela.yml
```

## Formato do achado

```python
class Finding(BaseModel):
    arquivo: str
    linha: int            # linha no arquivo novo
    severidade: Severity  # baixa | media | alta | critica
    categoria: str        # ex.: "SQL injection", "XSS", "segredo no código"
    cwe: str | None       # ex.: "CWE-89"
    regra: str            # id da regra, ex.: "sql-concatenacao"
    explicacao: str       # em português, curta e específica
    correcao: str         # sugestão concreta
```

## Regras de código

- Mensagens para o usuário, explicações dos achados e docs em **português**.
- Funções pequenas e tipadas. Sem abstrações que ainda não são necessárias.
- Cada regra em `regras.py` olha uma linha adicionada. Toda regra nova vem com testes: pelo menos um caso vulnerável que dispara e um seguro parecido que não dispara.
- Regras novas ou alteradas devem ser medidas nos evals; guardar os resultados antes e depois.
- O comando `revisar` sai com código 1 se houver achado de severidade alta ou crítica, 0 caso contrário (Fase 3).
- Nunca commitar segredos.

## Comandos

```bash
source .venv/bin/activate
pip install -e ".[dev]"
pytest
sentinela revisar caminho/do.diff
sentinela varrer caminho/do/projeto -x tests
git diff main | sentinela revisar -
python evals/run_evals.py
```

## Como trabalhar neste projeto

- Uma fase do `ROTEIRO.md` por vez. Não adiantar fases.
- Depois de cada parte, explicar em poucas linhas o que foi feito e por quê, para o Carlos conseguir reexplicar.
- Se algo for decisão de design (formato, nome, estrutura), propor e justificar antes de gerar muito código.
