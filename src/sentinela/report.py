"""Formata os achados em terminal (Rich), markdown (comentário de PR) e JSON."""

import json
from enum import Enum

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding

from sentinela.models import BLOQUEANTES, Finding, Severity

# Marcador invisível: a Action (Fase 5) usa para achar e atualizar o próprio comentário.
MARCADOR_MARKDOWN = "<!-- sentinela -->"

_PRIORIDADE = {Severity.critica: 0, Severity.alta: 1, Severity.media: 2, Severity.baixa: 3}
_COR = {
    Severity.critica: "bold white on red",
    Severity.alta: "bold red",
    Severity.media: "yellow",
    Severity.baixa: "cyan",
}


class Formato(str, Enum):
    terminal = "terminal"
    markdown = "markdown"
    json = "json"


def tem_bloqueante(achados: list[Finding]) -> bool:
    return any(a.severidade in BLOQUEANTES for a in achados)


def _mais_graves_primeiro(achados: list[Finding]) -> list[Finding]:
    # sorted é estável: dentro da mesma severidade, mantém a ordem de arquivo e linha.
    return sorted(achados, key=lambda a: _PRIORIDADE[a.severidade])


def _resumo(achados: list[Finding]) -> str:
    if not achados:
        return "Nenhum problema encontrado."
    partes = [
        f"{sum(a.severidade is s for a in achados)} {s.value}"
        for s in sorted(Severity, key=_PRIORIDADE.get)
        if any(a.severidade is s for a in achados)
    ]
    return f"{len(achados)} achado(s): {', '.join(partes)}."


def imprimir_terminal(achados: list[Finding], console: Console) -> None:
    for a in _mais_graves_primeiro(achados):
        cwe = f" · {a.cwe}" if a.cwe else ""
        console.print(
            f"[{_COR[a.severidade]}] {a.severidade.value.upper()} [/] "
            f"[bold]{escape(a.categoria)}[/]  [dim]{escape(a.arquivo)}:{a.linha}{cwe}[/]"
        )
        console.print(Padding(escape(a.explicacao), (0, 0, 0, 2)))
        console.print(Padding(f"[green]Correção:[/] {escape(a.correcao)}", (0, 0, 1, 2)))
    console.print(f"[bold]{_resumo(achados)}[/]")


def formatar_markdown(achados: list[Finding]) -> str:
    linhas = [MARCADOR_MARKDOWN, "## Sentinela", ""]
    if not achados:
        linhas.append("Nenhum problema de segurança encontrado nas linhas adicionadas.")
        return "\n".join(linhas) + "\n"

    linhas += [_resumo(achados), ""]
    for a in _mais_graves_primeiro(achados):
        cwe = f" ({a.cwe})" if a.cwe else ""
        linhas += [
            f"### {a.severidade.value.upper()}: {a.categoria}{cwe}",
            f"`{a.arquivo}:{a.linha}`",
            "",
            a.explicacao,
            "",
            f"**Correção:** {a.correcao}",
            "",
        ]
    return "\n".join(linhas)


def formatar_json(achados: list[Finding]) -> str:
    dados = {
        "total": len(achados),
        "achados": [a.model_dump(mode="json") for a in _mais_graves_primeiro(achados)],
    }
    return json.dumps(dados, ensure_ascii=False, indent=2)
