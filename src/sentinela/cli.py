import sys
from pathlib import Path
from typing import Optional

import typer

from sentinela.diff import parse_diff

app = typer.Typer(help="Sentinela: revisor de segurança para diffs de código.")


@app.callback()
def principal() -> None:
    """Mantém `revisar` como subcomando, mesmo com um único comando."""


@app.command()
def revisar(
    arquivo: Optional[Path] = typer.Argument(
        None, help="Arquivo .diff a revisar. Omita ou use '-' para ler da entrada padrão."
    ),
) -> None:
    """Lê um diff unificado e lista o que há de código novo para revisar."""
    if arquivo is None or str(arquivo) == "-":
        texto = sys.stdin.read()
    elif arquivo.is_file():
        texto = arquivo.read_text(encoding="utf-8")
    else:
        typer.echo(f"Arquivo não encontrado: {arquivo}", err=True)
        raise typer.Exit(2)

    trechos = parse_diff(texto)
    if not trechos:
        typer.echo("Nenhuma linha adicionada no diff.")
        return

    # Fase 1: ainda sem IA, só mostra o que seria enviado para revisão.
    for trecho in trechos:
        typer.echo(f"{trecho.arquivo}: {len(trecho.linhas_adicionadas)} linha(s) adicionada(s)")
