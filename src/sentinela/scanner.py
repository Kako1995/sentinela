"""Aplica as regras (por linha) e a análise por AST às linhas adicionadas de um diff."""

import re
from pathlib import PurePosixPath

from sentinela.ast_js import EXTENSOES_JS, analisar_ast_js
from sentinela.ast_python import ResultadoAst, analisar_ast
from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.models import Finding
from sentinela.regras import ABRE_TEMPLATE_SQL, REGRAS, Regra

COMENTARIO = re.compile(r"^\s*(#|//|/\*|\*)")

# Em arquivos Python/JS que a AST conseguiu analisar, estas regras por linha são dispensadas:
# a AST cobre os mesmos casos com menos falsos positivos (sabe de onde vem o dado).
COBERTAS_PELA_AST = {"path-traversal-entrada", "ssrf-url-da-entrada"}

# Lookahead com quantificador (ex.: ".*" em sql-concatenacao) tem custo pior-caso quadrático
# no tamanho da entrada quando ela não casa. Linha acima deste limite pula as regras por
# linha (a análise por AST, que lê o arquivo de outro jeito, continua valendo). O nome e o
# conteúdo do arquivo vêm de um diff possivelmente malicioso, então isto é defesa, não só
# desempenho.
TAMANHO_MAXIMO_LINHA = 2000

_RE_ABRE_TEMPLATE_SQL = re.compile(ABRE_TEMPLATE_SQL)


def _linhas_em_template_sql(linhas: list[LinhaAdicionada]) -> set[int]:
    """Números de linha dentro de um template com tag (sql`...`, $queryRaw`...`) que abre numa
    linha e só fecha numa linha seguinte: a tag ainda parametriza cada ${x}, mas a exceção de
    sql-concatenacao só olha a própria linha, então não vê a tag quando ela está numa linha
    anterior. Isto cobre esse caso; a exceção continua cuidando do caso de uma linha só."""
    dentro: set[int] = set()
    aberto = False
    for linha in linhas:
        texto = linha.texto
        if aberto:
            dentro.add(linha.numero)
            fecha = "`" in texto
        else:
            m = _RE_ABRE_TEMPLATE_SQL.search(texto)
            if not m:
                continue
            fecha = "`" in texto[m.end() :]
            if not fecha:
                dentro.add(linha.numero)
        aberto = not fecha
    return dentro


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


def _resultado_ast(trecho: TrechoArquivo) -> ResultadoAst | None:
    """Análise por AST do arquivo, ou None se não foi possível (sem fonte, não é .py, erro de sintaxe)."""
    if trecho.fonte is None:
        return None
    if trecho.arquivo.endswith(".py"):
        return analisar_ast(trecho.arquivo, trecho.fonte)
    if PurePosixPath(trecho.arquivo).suffix in EXTENSOES_JS:
        return analisar_ast_js(trecho.arquivo, trecho.fonte)
    return None


def analisar(trechos: list[TrechoArquivo], regras: list[Regra] = REGRAS) -> list[Finding]:
    """Devolve os achados na ordem dos arquivos e das linhas, sem repetir (linha, categoria)."""
    achados: list[Finding] = []
    for trecho in trechos:
        resultado = _resultado_ast(trecho)
        ativas = [r for r in regras if resultado is None or r.id not in COBERTAS_PELA_AST]
        texto_solto = resultado.linhas_de_texto if resultado else set()
        adicionadas = {l.numero for l in trecho.linhas_adicionadas}
        linhas = trecho.linhas_adicionadas
        em_template_sql = _linhas_em_template_sql(linhas)
        do_trecho: list[Finding] = []

        for i, linha in enumerate(linhas):
            if COMENTARIO.match(linha.texto) or linha.numero in texto_solto:
                continue
            if len(linha.texto) > TAMANHO_MAXIMO_LINHA:
                continue
            for regra in ativas:
                if regra.id == "sql-concatenacao" and linha.numero in em_template_sql:
                    continue
                if regra.janela == 1:
                    casou = regra.casa(linha.texto)
                elif regra.gatilho and regra.gatilho not in linha.texto:
                    continue  # barato: evita juntar linhas em todo o arquivo
                else:
                    casou = regra.casa(_janela(linhas, i, regra.janela), limite_inicio=len(linha.texto))
                if casou:
                    do_trecho.append(
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

        do_trecho += [a for a in (resultado.achados if resultado else []) if a.linha in adicionadas]
        vistos: set[tuple[int, str]] = set()
        for a in sorted(do_trecho, key=lambda f: f.linha):  # sorted é estável: regras antes da AST
            if (a.linha, a.categoria) not in vistos:
                vistos.add((a.linha, a.categoria))
                achados.append(a)
    return achados
