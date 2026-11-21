import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from sentinela.config import NOME_ARQUIVO, Config, carregar as carregar_config
from sentinela.diff import TrechoArquivo, parse_diff
from sentinela.models import Finding
from sentinela.report import (
    Formato,
    formatar_json,
    formatar_markdown,
    formatar_sarif,
    imprimir_terminal,
    tem_bloqueante,
)
from sentinela.scanner import TAMANHO_MAXIMO_LINHA, analisar
from sentinela.varredura import anexar_fontes
from sentinela.varredura import varrer as varrer_pasta

app = typer.Typer(help="Sentinela: revisor de segurança para diffs de código.")

OPCAO_FORMATO = typer.Option(
    Formato.terminal, "--formato", "-f",
    help="Formato do relatório: terminal, markdown, json ou sarif (pra GitHub Code Scanning).",
)
OPCAO_NOTA = typer.Option(
    False, "--nota",
    help="Mostra uma nota de 0 a 10, com a fórmula e o aviso de limitação junto (não é nota de segurança).",
)


@app.callback()
def principal() -> None:
    """Mantém os comandos como subcomandos, mesmo quando há só um."""


def _avisar_linhas_longas(trechos: list[TrechoArquivo]) -> None:
    """Avisa quantas linhas passaram de TAMANHO_MAXIMO_LINHA e por isso não foram
    checadas pelas regras por linha (scanner.py)."""
    n = sum(1 for t in trechos for l in t.linhas_adicionadas if len(l.texto) > TAMANHO_MAXIMO_LINHA)
    if n:
        typer.echo(
            f"{n} linha(s) com mais de {TAMANHO_MAXIMO_LINHA} caracteres não passaram pelas regras "
            "por linha (SVG, bundle minificado ou dado numa linha só costumam ser a causa).",
            err=True,
        )


def _config(pasta: Path) -> Config:
    """Lê .sentinela.toml em `pasta` (ou na pasta-mãe, se `pasta` for um arquivo) e avisa se ele
    tiver algum problema — nunca impede a análise de rodar, só volta ao padrão (nada desativado)."""
    config = carregar_config(pasta if pasta.is_dir() else pasta.parent)
    if config.erro:
        typer.echo(f"{NOME_ARQUIVO}: {config.erro} (rodando com o padrão: nada desativado).", err=True)
    return config


def _emitir(achados: list[Finding], formato: Formato, nota: bool = False) -> None:
    """Imprime o relatório no formato pedido e sai com 1 se houver achado alto ou crítico."""
    if formato is Formato.json:
        typer.echo(formatar_json(achados, nota))
    elif formato is Formato.markdown:
        typer.echo(formatar_markdown(achados, nota))
    elif formato is Formato.sarif:
        typer.echo(formatar_sarif(achados))  # --nota não se aplica: SARIF é lido por ferramenta, não por gente
    else:
        imprimir_terminal(achados, Console(), nota)

    if tem_bloqueante(achados):
        raise typer.Exit(1)


@app.command()
def revisar(
    arquivo: Optional[Path] = typer.Argument(
        None, help="Arquivo .diff a revisar. Omita ou use '-' para ler da entrada padrão."
    ),
    formato: Formato = OPCAO_FORMATO,
    raiz: Optional[Path] = typer.Option(
        None, "--raiz",
        help="Pasta do repositório. Com ela, os arquivos .py do diff são lidos por inteiro e passam "
        "pela análise por AST (acha mais, com menos falsos positivos).",
    ),
    nota: bool = OPCAO_NOTA,
) -> None:
    """Lê um diff unificado e aponta vulnerabilidades nas linhas adicionadas.

    Sai com código 1 se houver achado de severidade alta ou crítica, 0 se não,
    e 2 se o arquivo não existir.
    """
    if arquivo is None or str(arquivo) == "-":
        texto = sys.stdin.read()
    elif arquivo.is_file():
        texto = arquivo.read_text(encoding="utf-8")
    else:
        typer.echo(f"Arquivo não encontrado: {arquivo}", err=True)
        raise typer.Exit(2)

    trechos = parse_diff(texto)
    config = Config()
    if raiz is not None:
        if not raiz.is_dir():
            typer.echo(f"Pasta não encontrada: {raiz}", err=True)
            raise typer.Exit(2)
        sem_ast = anexar_fontes(trechos, raiz)
        if sem_ast:
            typer.echo(f"{sem_ast} arquivo(s) .py sem análise por AST (não encontrado em --raiz ou diferente do diff).", err=True)
        config = _config(raiz)
    _avisar_linhas_longas(trechos)
    # Diff vazio ou sem linhas adicionadas é um relatório sem achados, no formato pedido.
    _emitir(analisar(trechos, desativadas=config.regras_desativadas), formato, nota)


@app.command()
def varrer(
    pasta: Path = typer.Argument(..., help="Pasta (ou arquivo) a analisar por inteiro."),
    formato: Formato = OPCAO_FORMATO,
    excluir: list[str] = typer.Option(
        [], "--excluir", "-x", help="Caminho ou padrão a ignorar. Pode repetir a opção."
    ),
    nota: bool = OPCAO_NOTA,
) -> None:
    """Analisa todos os arquivos de texto de uma pasta, não só um diff.

    Pula dependências (node_modules, .venv...), binários e arquivos grandes. Tem mais
    ruído que `revisar`: trate o resultado como uma lista para conferir. Mesmos códigos
    de saída do `revisar`.
    """
    if not pasta.exists():
        typer.echo(f"Caminho não encontrado: {pasta}", err=True)
        raise typer.Exit(2)

    config = _config(pasta)
    trechos = varrer_pasta(pasta, [*excluir, *config.ignorar])
    # Fora da saída principal, para json e markdown continuarem sendo só o relatório.
    typer.echo(f"{len(trechos)} arquivo(s) analisado(s).", err=True)
    _avisar_linhas_longas(trechos)
    _emitir(analisar(trechos, desativadas=config.regras_desativadas), formato, nota)
