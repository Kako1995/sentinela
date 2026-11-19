"""Roda o scanner nos casos de evals/casos/ e mostra precisão, recall e os erros.

Uso:
    python evals/run_evals.py --rotulo v1-baseline

Cada rodada é salva em evals/resultados/ com data e rótulo, para comparar antes e depois
de mudar as regras.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sentinela.avaliacao import (
    ResultadoCaso,
    avaliar,
    calcular_metricas,
    carregar_casos,
    recall_por_categoria,
)

RAIZ = Path(__file__).parent
PASTA_CASOS = RAIZ / "casos"
PASTA_RESULTADOS = RAIZ / "resultados"

console = Console()


def _pct(valor: float | None) -> str:
    return "n/a" if valor is None else f"{valor:.0%}"


def _commit() -> str | None:
    try:
        saida = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=RAIZ
        )
        return saida.stdout.strip() or None
    except OSError:
        return None


def _tabela_metricas(titulo: str, resultados: list[ResultadoCaso]) -> Table:
    m = calcular_metricas(resultados)
    tabela = Table(title=titulo, show_header=True)
    for coluna in ("casos", "TP", "FP", "FN", "TN", "precisão", "recall"):
        tabela.add_column(coluna, justify="right")
    tabela.add_row(
        str(len(resultados)), str(m.tp), str(m.fp), str(m.fn), str(m.tn), _pct(m.precisao), _pct(m.recall)
    )
    return tabela


def main(
    rotulo: str = typer.Option("sem-rotulo", help="Nome da rodada, ex.: v1-baseline."),
    salvar: bool = typer.Option(True, help="Salvar o resultado em evals/resultados/."),
) -> None:
    casos = carregar_casos(PASTA_CASOS)
    resultados = avaliar(casos)

    console.print(_tabela_metricas(f"Resultado geral ({rotulo})", resultados))

    por_origem = sorted({r.caso.origem for r in resultados})
    if len(por_origem) > 1:
        for origem in por_origem:
            doc = [r for r in resultados if r.caso.origem == origem]
            console.print(_tabela_metricas(f"Casos escritos por: {origem}", doc))

    categorias = Table(title="Recall por categoria", show_header=True)
    categorias.add_column("categoria")
    categorias.add_column("achados", justify="right")
    categorias.add_column("recall", justify="right")
    for categoria, (acertos, total) in recall_por_categoria(resultados).items():
        categorias.add_row(categoria, f"{acertos}/{total}", _pct(acertos / total))
    console.print(categorias)

    erros = [r for r in resultados if r.veredito in ("FN", "FP")]
    tabela_erros = Table(title=f"Erros ({len(erros)})", show_header=True)
    for coluna in ("caso", "erro", "esperado", "o scanner achou"):
        tabela_erros.add_column(coluna)
    for r in erros:
        tipo = "falso negativo" if r.veredito == "FN" else "falso positivo"
        esperado = r.caso.categoria_esperada or "(seguro)"
        tabela_erros.add_row(r.caso.id, tipo, esperado, ", ".join(r.categorias_achadas) or "nada")
    console.print(tabela_erros)

    if salvar:
        agora = datetime.now()
        m = calcular_metricas(resultados)
        PASTA_RESULTADOS.mkdir(exist_ok=True)
        destino = PASTA_RESULTADOS / f"{agora:%Y-%m-%d_%H%M%S}_{rotulo}.json"
        destino.write_text(
            json.dumps(
                {
                    "rotulo": rotulo,
                    "data": agora.isoformat(timespec="seconds"),
                    "commit": _commit(),
                    "metricas": {
                        "tp": m.tp, "fp": m.fp, "fn": m.fn, "tn": m.tn,
                        "precisao": m.precisao, "recall": m.recall,
                    },
                    "casos": [
                        {
                            "id": r.caso.id,
                            "origem": r.caso.origem,
                            "veredito": r.veredito,
                            "esperado": r.caso.categoria_esperada,
                            "achadas": r.categorias_achadas,
                        }
                        for r in resultados
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        console.print(f"\nResultado salvo em [dim]{destino.relative_to(RAIZ.parent)}[/]")


if __name__ == "__main__":
    typer.run(main)
