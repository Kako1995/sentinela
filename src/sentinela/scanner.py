"""Aplica as regras às linhas adicionadas de um diff."""

import re

from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.models import Finding
from sentinela.regras import REGRAS, Regra

COMENTARIO = re.compile(r"^\s*(#|//|/\*|\*)")


def _janela(linhas: list[LinhaAdicionada], inicio: int, tamanho: int) -> str:
    """Junta até `tamanho` linhas SEGUIDAS no arquivo, começando em `inicio`.

    Num diff, as linhas adicionadas podem ter lacunas (contexto ou remoções no meio): só se
    junta enquanto os números são consecutivos, para não unir código que não é vizinho.
    """
    textos = [linhas[inicio].texto]
    for atual, anterior in zip(linhas[inicio + 1 : inicio + tamanho], linhas[inicio : inicio + tamanho - 1]):
        if atual.numero != anterior.numero + 1:
            break
        textos.append(atual.texto)
    return "\n".join(textos)


def analisar(trechos: list[TrechoArquivo], regras: list[Regra] = REGRAS) -> list[Finding]:
    """Devolve um achado por (linha, regra), na ordem dos arquivos e das linhas."""
    achados: list[Finding] = []
    for trecho in trechos:
        linhas = trecho.linhas_adicionadas
        for i, linha in enumerate(linhas):
            if COMENTARIO.match(linha.texto):
                continue
            for regra in regras:
                if regra.janela == 1:
                    casou = regra.casa(linha.texto)
                elif regra.gatilho and regra.gatilho not in linha.texto:
                    continue  # barato: evita juntar linhas em todo o arquivo
                else:
                    casou = regra.casa(_janela(linhas, i, regra.janela), limite_inicio=len(linha.texto))
                if casou:
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
