"""Lógica dos evals: carrega casos rotulados, roda o scanner e calcula precisão e recall.

Como os números são definidos (nível de caso, não de linha):
- "vulnerável" é a classe positiva.
- TP: caso vulnerável em que o scanner achou a categoria esperada.
- FN: caso vulnerável em que a categoria esperada não apareceu (nenhum achado, ou só
  achados de outra categoria).
- FP: caso seguro em que o scanner achou qualquer coisa.
- TN: caso seguro sem achados.
- precisão = TP / (TP + FP)   "dos alertas que ele deu, quantos eram reais"
- recall   = TP / (TP + FN)   "das vulnerabilidades que existem, quantas ele achou"
"""

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, model_validator

from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.models import Finding
from sentinela.regras import REGRAS, Regra
from sentinela.scanner import analisar

EXTENSOES = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java"}


class Caso(BaseModel):
    id: str = ""  # preenchido com o nome do arquivo
    linguagem: str
    vulneravel: bool
    categoria_esperada: str | None = None
    origem: str = "claude"  # quem escreveu: "claude", "claude-dificil" ou "carlos"
    nota: str = ""  # por que o caso é difícil (só para quem lê)
    codigo: str

    @model_validator(mode="after")
    def _categoria_combina_com_rotulo(self) -> "Caso":
        if self.vulneravel and not self.categoria_esperada:
            raise ValueError("caso vulnerável precisa de categoria_esperada")
        if not self.vulneravel and self.categoria_esperada:
            raise ValueError("caso seguro não tem categoria_esperada")
        return self


Veredito = Literal["TP", "FN", "FP", "TN"]


@dataclass
class ResultadoCaso:
    caso: Caso
    veredito: Veredito
    categorias_achadas: list[str]


@dataclass
class Metricas:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precisao(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None


def carregar_casos(pasta: Path) -> list[Caso]:
    casos = []
    for arquivo in sorted(pasta.glob("*.json")):
        dados = json.loads(arquivo.read_text(encoding="utf-8"))
        casos.append(Caso(id=arquivo.stem, **dados))
    return casos


def _como_trecho(caso: Caso) -> TrechoArquivo:
    """Trata o código inteiro do caso como linhas adicionadas de um arquivo novo."""
    extensao = EXTENSOES.get(caso.linguagem, "txt")
    linhas = [LinhaAdicionada(i, t) for i, t in enumerate(caso.codigo.splitlines(), start=1)]
    fonte = caso.codigo if caso.linguagem == "python" else None  # habilita a análise por AST
    return TrechoArquivo(arquivo=f"{caso.id}.{extensao}", linhas_adicionadas=linhas, fonte=fonte)


def avaliar_caso(caso: Caso, regras: list[Regra] = REGRAS) -> ResultadoCaso:
    achados: list[Finding] = analisar([_como_trecho(caso)], regras)
    categorias = sorted({a.categoria for a in achados})
    if caso.vulneravel:
        veredito: Veredito = "TP" if caso.categoria_esperada in categorias else "FN"
    else:
        veredito = "FP" if achados else "TN"
    return ResultadoCaso(caso, veredito, categorias)


def avaliar(casos: list[Caso], regras: list[Regra] = REGRAS) -> list[ResultadoCaso]:
    return [avaliar_caso(c, regras) for c in casos]


def calcular_metricas(resultados: list[ResultadoCaso]) -> Metricas:
    contagem = {v: sum(r.veredito == v for r in resultados) for v in ("TP", "FP", "FN", "TN")}
    return Metricas(contagem["TP"], contagem["FP"], contagem["FN"], contagem["TN"])


def recall_por_categoria(resultados: list[ResultadoCaso]) -> dict[str, tuple[int, int]]:
    """Para cada categoria esperada: (achados, total). Só conta casos vulneráveis."""
    tabela: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in resultados:
        if r.caso.vulneravel:
            tabela[r.caso.categoria_esperada][1] += 1
            tabela[r.caso.categoria_esperada][0] += r.veredito == "TP"
    return {categoria: (acertos, total) for categoria, (acertos, total) in sorted(tabela.items())}
