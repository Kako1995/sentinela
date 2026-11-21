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


# Quanto cada achado tira da nota (0 a 10). Pesos simples de propósito: a fórmula precisa caber
# numa frase para quem lê confiar nela, não só no número.
_PESO_NOTA = {Severity.critica: 3, Severity.alta: 2, Severity.media: 1, Severity.baixa: 0.5}
FORMULA_NOTA = (
    "Começa em 10; cada achado crítico tira 3, alta tira 2, média tira 1, baixa tira 0,5. "
    "Nunca passa de 0 nem de 10."
)
# Não é "nota de segurança": uma nota alta não quer dizer que o código é seguro, só que as regras
# e a AST não acharam muita coisa nas linhas analisadas — e elas têm limites conhecidos (ver README).
AVISO_NOTA = (
    "Baseada só no que as regras e a análise por AST enxergam nas linhas analisadas. "
    "Não é uma nota de segurança do projeto, nem substitui revisão humana ou um pentest."
)


def calcular_nota(achados: list[Finding]) -> float:
    pontos = sum(_PESO_NOTA[a.severidade] for a in achados)
    return max(0.0, min(10.0, 10.0 - pontos))


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


def imprimir_terminal(achados: list[Finding], console: Console, nota: bool = False) -> None:
    for a in _mais_graves_primeiro(achados):
        cwe = f" · {a.cwe}" if a.cwe else ""
        console.print(
            f"[{_COR[a.severidade]}] {a.severidade.value.upper()} [/] "
            f"[bold]{escape(a.categoria)}[/]  [dim]{escape(a.arquivo)}:{a.linha}{cwe}[/]"
        )
        console.print(Padding(escape(a.explicacao), (0, 0, 0, 2)))
        console.print(Padding(f"[green]Correção:[/] {escape(a.correcao)}", (0, 0, 1, 2)))
    console.print(f"[bold]{_resumo(achados)}[/]")
    if nota:
        console.print()
        console.print(f"[bold]Nota do Sentinela: {calcular_nota(achados):.1f}/10[/]")
        console.print(f"[dim]{escape(FORMULA_NOTA)}[/]")
        console.print(f"[dim]{escape(AVISO_NOTA)}[/]")


def formatar_markdown(achados: list[Finding], nota: bool = False) -> str:
    linhas = [MARCADOR_MARKDOWN, "## Sentinela", ""]
    if not achados:
        linhas.append("Nenhum problema de segurança encontrado nas linhas adicionadas.")
        if nota:
            linhas += ["", f"**Nota do Sentinela: {calcular_nota(achados):.1f}/10**", "", FORMULA_NOTA, "", AVISO_NOTA]
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
    if nota:
        linhas += [f"**Nota do Sentinela: {calcular_nota(achados):.1f}/10**", "", FORMULA_NOTA, "", AVISO_NOTA, ""]
    return "\n".join(linhas)


def formatar_json(achados: list[Finding], nota: bool = False) -> str:
    dados = {
        "total": len(achados),
        "achados": [a.model_dump(mode="json") for a in _mais_graves_primeiro(achados)],
    }
    if nota:
        dados["nota"] = {"valor": calcular_nota(achados), "formula": FORMULA_NOTA, "aviso": AVISO_NOTA}
    return json.dumps(dados, ensure_ascii=False, indent=2)
