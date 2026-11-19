import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from sentinela.diff import parse_diff
from sentinela.report import (
    Formato,
    formatar_json,
    formatar_markdown,
    imprimir_terminal,
    tem_bloqueante,
)
from sentinela.scanner import analisar

app = typer.Typer(help="Sentinela: revisor de segurança para diffs de código.")


@app.callback()
def principal() -> None:
    """Mantém `revisar` como subcomando, mesmo com um único comando."""


@app.command()
def revisar(
    arquivo: Optional[Path] = typer.Argument(
        None, help="Arquivo .diff a revisar. Omita ou use '-' para ler da entrada padrão."
    ),
    formato: Formato = typer.Option(
        Formato.terminal, "--formato", "-f", help="Formato do relatório."
    ),
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

    # Diff vazio ou sem linhas adicionadas é um relatório sem achados, no formato pedido.
    achados = analisar(parse_diff(texto))

    if formato is Formato.json:
        typer.echo(formatar_json(achados))
    elif formato is Formato.markdown:
        typer.echo(formatar_markdown(achados))
    else:
        imprimir_terminal(achados, Console())

    if tem_bloqueante(achados):
        raise typer.Exit(1)
