import sys
from pathlib import Path
from typing import Optional

import typer

from sentinela.diff import parse_diff
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
) -> None:
    """Lê um diff unificado e aponta vulnerabilidades nas linhas adicionadas."""
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

    achados = analisar(trechos)
    if not achados:
        typer.echo("Nenhum problema encontrado.")
        return

    # Formato simples por enquanto; relatório colorido, markdown/JSON e exit code vêm na Fase 3.
    for a in achados:
        cwe = f", {a.cwe}" if a.cwe else ""
        typer.echo(f"{a.arquivo}:{a.linha} [{a.severidade.value}] {a.categoria} ({a.regra}{cwe})")
        typer.echo(f"  {a.explicacao}")
        typer.echo(f"  Correção: {a.correcao}")
    typer.echo(f"\n{len(achados)} achado(s).")
