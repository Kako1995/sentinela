# Sentinela

Ferramenta de linha de comando que revisa diffs de código em busca de vulnerabilidades de segurança **usando regras (regex)**, e roda como GitHub Action em pull requests.

**Sem IA e sem chamadas de rede.** Detecção por regras por linha e por análise de AST (Python, JavaScript e TypeScript). Decisão do Carlos: a detecção é determinística, gratuita e offline. Não adicionar dependência de LLM nem chave de API.

O objetivo do projeto é aprendizado e portfólio: o Carlos precisa entender e conseguir explicar cada parte. O diferencial são os **evals** (medir precisão e recall das regras).

## Stack

- Python 3.10+ (alvo: 3.12)
- CLI: Typer
- Modelos: Pydantic v2
- Análise de JS/TS: tree-sitter (com as gramáticas de JavaScript e TypeScript); a de Python usa o `ast` da biblioteca padrão
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
  regras.py     # regras por linha: regex por categoria de vulnerabilidade
  ast_python.py # análise por AST de Python: origem->uso do dado, SQL multilinha, autorização
  ast_js.py     # análise por AST de JS/TS (tree-sitter): Express, Next.js (route handlers, server actions), Supabase
  scanner.py    # aplica as regras às linhas adicionadas
  config.py     # lê .sentinela.toml (regras desativadas, caminhos extras a ignorar)
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
- Regras novas ou alteradas devem ser medidas nos evals; guardar os resultados antes e depois, e conferir que nenhum acerto (TP) da versão anterior foi perdido.
- A AST (Python e JS/TS) só lê arquivos dentro de `--raiz`, sem links simbólicos e só se baterem com o diff (o nome vem de um diff possivelmente malicioso).
- Linha acima de `TAMANHO_MAXIMO_LINHA` (`scanner.py`) não passa pelas regras por linha: regex com lookahead (ex.: `sql-concatenacao`) tem custo quadrático numa linha sem quebra de verdade (SVG, bundle minificado), e isso já travou a varredura por minutos. A CLI avisa quantas linhas foram puladas.
- Nos casos de eval, escreva o conjunto novo ANTES de implementar o que ele mede, e confira que nenhum TP anterior foi perdido.
- Uma regra que precisa ver várias linhas usa `janela` e `gatilho` (ver `regras.py`); o scanner só junta linhas vizinhas no arquivo.
- O comando `revisar` sai com código 1 se houver achado de severidade alta ou crítica, 0 caso contrário (Fase 3).
- Nunca commitar segredos.
- `--nota` (0 a 10, `report.py`) é opcional (`revisar`/`varrer`) e nunca chamada de "nota de segurança": a fórmula é simples e visível (cabe numa frase) e vem sempre com o aviso de que só cobre o que as regras e a AST enxergam.

## Comandos

```bash
source .venv/bin/activate
pip install -e ".[dev]"
pytest
sentinela revisar caminho/do.diff
sentinela varrer caminho/do/projeto -x tests
git diff main | sentinela revisar - --raiz .   # com AST nos .py/.js/.ts do diff
git diff main | sentinela revisar -
sentinela revisar caminho/do.diff --nota   # nota de 0 a 10, com fórmula e aviso junto (ver report.py)
python evals/run_evals.py
```

## Como trabalhar neste projeto

- Uma fase do `ROTEIRO.md` por vez. Não adiantar fases.
- Depois de cada parte, explicar em poucas linhas o que foi feito e por quê, para o Carlos conseguir reexplicar.
- Se algo for decisão de design (formato, nome, estrutura), propor e justificar antes de gerar muito código.
