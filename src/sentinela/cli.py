import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from sentinela.diff import parse_diff
from sentinela.models import Finding
from sentinela.report import (
    Formato,
    formatar_json,
    formatar_markdown,
    imprimir_terminal,
    tem_bloqueante,
)
from sentinela.scanner import analisar
from sentinela.varredura import varrer as varrer_pasta

app = typer.Typer(help="Sentinela: revisor de segurança para diffs de código.")

OPCAO_FORMATO = typer.Option(Formato.terminal, "--formato", "-f", help="Formato do relatório.")


@app.callback()
def principal() -> None:
    """Mantém os comandos como subcomandos, mesmo quando há só um."""


def _emitir(achados: list[Finding], formato: Formato) -> None:
    """Imprime o relatório no formato pedido e sai com 1 se houver achado alto ou crítico."""
    if formato is Formato.json:
        typer.echo(formatar_json(achados))
    elif formato is Formato.markdown:
        typer.echo(formatar_markdown(achados))
    else:
        imprimir_terminal(achados, Console())

    if tem_bloqueante(achados):
        raise typer.Exit(1)


@app.command()
def revisar(
    arquivo: Optional[Path] = typer.Argument(
        None, help="Arquivo .diff a revisar. Omita ou use '-' para ler da entrada padrão."
    ),
    formato: Formato = OPCAO_FORMATO,
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
    _emitir(analisar(parse_diff(texto)), formato)


@app.command()
def varrer(
    pasta: Path = typer.Argument(..., help="Pasta (ou arquivo) a analisar por inteiro."),
    formato: Formato = OPCAO_FORMATO,
    excluir: list[str] = typer.Option(
        [], "--excluir", "-x", help="Caminho ou padrão a ignorar. Pode repetir a opção."
    ),
) -> None:
    """Analisa todos os arquivos de texto de uma pasta, não só um diff.

    Pula dependências (node_modules, .venv...), binários e arquivos grandes. Tem mais
    ruído que `revisar`: trate o resultado como uma lista para conferir. Mesmos códigos
    de saída do `revisar`.
    """
    if not pasta.exists():
        typer.echo(f"Caminho não encontrado: {pasta}", err=True)
        raise typer.Exit(2)

    trechos = varrer_pasta(pasta, excluir)
    # Fora da saída principal, para json e markdown continuarem sendo só o relatório.
    typer.echo(f"{len(trechos)} arquivo(s) analisado(s).", err=True)
    _emitir(analisar(trechos), formato)
