"""Aplica as regras às linhas adicionadas de um diff."""

import re

from sentinela.diff import TrechoArquivo
from sentinela.models import Finding
from sentinela.regras import REGRAS, Regra

COMENTARIO = re.compile(r"^\s*(#|//|/\*|\*)")


def analisar(trechos: list[TrechoArquivo], regras: list[Regra] = REGRAS) -> list[Finding]:
    """Devolve um achado por (linha, regra), na ordem dos arquivos e das linhas."""
    achados: list[Finding] = []
    for trecho in trechos:
        for linha in trecho.linhas_adicionadas:
            if COMENTARIO.match(linha.texto):
                continue
            for regra in regras:
                if regra.casa(linha.texto):
                    achados.append(
                        Finding(
                            arquivo=trecho.arquivo,
                            linha=linha.numero,
                            severidade=regra.severidade,
                            categoria=regra.categoria,
                            cwe=regra.cwe,
                            regra=regra.id,
                            explicacao=regra.explicacao,
                            correcao=regra.correcao,
                        )
                    )
    return achados
