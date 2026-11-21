"""Roda o scanner nos casos de evals/casos/ e mostra precisão, recall e os erros.

Uso:
    python evals/run_evals.py --rotulo v1-baseline

Cada rodada é salva em evals/resultados/ com data e rótulo, para comparar antes e depois
de mudar as regras.

Trava de regressão (usada no CI e também no pytest):
    python evals/run_evals.py --verificar            # compara cada caso com evals/baseline.json
    python evals/run_evals.py --atualizar-baseline   # grava a rodada de agora como a nova baseline

`--verificar` sai com 0 (tudo igual), 1 (REGRESSÃO: um acerto virou erro, ou um caso sumiu) ou 2 (nada piorou,
mas a baseline está desatualizada: melhorias, casos novos). Os códigos 1 e 2 reprovam o CI.
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sentinela.avaliacao import (
    DiferencaBaseline,
    ResultadoCaso,
    avaliar,
    calcular_metricas,
    carregar_casos,
    comparar_com_baseline,
    ler_baseline,
    recall_por_categoria,
    serializar_baseline,
    veredito_por_caso,
)

RAIZ = Path(__file__).parent
PASTA_CASOS = RAIZ / "casos"
PASTA_RESULTADOS = RAIZ / "resultados"
ARQUIVO_BASELINE = RAIZ / "baseline.json"

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


COMANDO_ATUALIZAR = "python evals/run_evals.py --atualizar-baseline"


def _linhas_da_diferenca(d: DiferencaBaseline) -> list[str]:
    """Texto simples (sem cor) do que mudou em relação à baseline: serve para o terminal e para o resumo do CI."""
    linhas: list[str] = []
    if d.regressoes:
        linhas.append(f"REGRESSÃO: {len(d.regressoes)} caso(s) que acertavam e agora erram:")
        linhas += [f"  - {id_}: {antes} -> {agora}" for id_, antes, agora in d.regressoes]
    if d.removidos:
        linhas.append(f"CASO(S) QUE SUMIRAM da avaliação ({len(d.removidos)}), apagados ou renomeados:")
        linhas += [f"  - {id_}" for id_ in d.removidos]
    if d.melhorias:
        linhas.append(f"Melhorias: {len(d.melhorias)} caso(s) que erravam e agora acertam:")
        linhas += [f"  - {id_}: {antes} -> {agora}" for id_, antes, agora in d.melhorias]
    if d.novos:
        linhas.append(f"Casos novos, ainda fora da baseline: {len(d.novos)}")
        linhas += [f"  - {id_}: {veredito}" for id_, veredito in d.novos]
    if d.outras:
        linhas.append(f"Outras mudanças (acerto -> acerto, ex.: rótulo do caso mudou): {len(d.outras)}")
        linhas += [f"  - {id_}: {antes} -> {agora}" for id_, antes, agora in d.outras]
    return linhas


def _resumo_para_o_github(resultados: list[ResultadoCaso], d: DiferencaBaseline, codigo: int) -> None:
    """No GitHub Actions, mostra o resultado na página da execução ($GITHUB_STEP_SUMMARY)."""
    destino = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destino:
        return
    m = calcular_metricas(resultados)
    estado = {0: "✅ igual à baseline", 1: "❌ REGRESSÃO", 2: "⚠️ baseline desatualizada"}[codigo]
    texto = [
        f"## Evals: {estado}",
        "",
        "| casos | TP | FP | FN | TN | precisão | recall |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {len(resultados)} | {m.tp} | {m.fp} | {m.fn} | {m.tn} | {_pct(m.precisao)} | {_pct(m.recall)} |",
    ]
    detalhes = _linhas_da_diferenca(d)
    if detalhes:
        texto += ["", "```", *detalhes, "```"]
    if codigo == 2:
        texto += ["", f"Nada piorou, mas a baseline não reflete esta rodada. Rode `{COMANDO_ATUALIZAR}` e commite `evals/baseline.json`."]
    with open(destino, "a", encoding="utf-8") as f:
        f.write("\n".join(texto) + "\n")


def _verificar(resultados: list[ResultadoCaso]) -> int:
    """Compara com evals/baseline.json. Devolve o código de saída (0 igual, 1 regressão, 2 baseline desatualizada)."""
    if not ARQUIVO_BASELINE.exists():
        console.print(f"[red]Não achei {ARQUIVO_BASELINE.name}.[/] Gere com: {COMANDO_ATUALIZAR}")
        return 1
    d = comparar_com_baseline(ler_baseline(ARQUIVO_BASELINE.read_text(encoding="utf-8")), veredito_por_caso(resultados))
    codigo = 1 if d.quebrou else 2 if d.desatualizada else 0
    console.print()
    if codigo == 0:
        console.print("[green]Trava de regressão: nenhum caso mudou em relação à baseline.[/]")
    else:
        for linha in _linhas_da_diferenca(d):
            console.print(linha, markup=False, highlight=False)
        if codigo == 1:
            console.print("\n[red]Reprovado: algo que já funcionava piorou.[/] Corrija a regra (ou, se a mudança é "
                          "intencional, justifique no PR e atualize a baseline).")
        else:
            console.print(f"\n[yellow]Nada piorou, mas a baseline está desatualizada.[/] Rode: {COMANDO_ATUALIZAR} "
                          "e commite evals/baseline.json.")
    _resumo_para_o_github(resultados, d, codigo)
    return codigo


def main(
    rotulo: str = typer.Option("sem-rotulo", help="Nome da rodada, ex.: v1-baseline."),
    salvar: bool = typer.Option(True, help="Salvar o resultado em evals/resultados/."),
    verificar: bool = typer.Option(False, "--verificar", help="Trava de regressão: compara com evals/baseline.json."),
    atualizar_baseline: bool = typer.Option(
        False, "--atualizar-baseline", help="Grava a rodada de agora em evals/baseline.json."
    ),
) -> None:
    casos = carregar_casos(PASTA_CASOS)
    resultados = avaliar(casos)
    if verificar or atualizar_baseline:
        salvar = False  # modo de conferência/atualização não enche evals/resultados/ de arquivos

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

    if atualizar_baseline:
        ARQUIVO_BASELINE.write_text(serializar_baseline(resultados), encoding="utf-8")
        console.print(f"\nBaseline gravada em [dim]{ARQUIVO_BASELINE.relative_to(RAIZ.parent)}[/] ({len(resultados)} casos).")
        return
    if verificar:
        raise typer.Exit(_verificar(resultados))

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
