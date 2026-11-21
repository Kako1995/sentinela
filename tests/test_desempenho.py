"""Regras por linha não podem travar numa linha muito longa.

Regex com quantificador dentro de lookahead (ex.: ".*" em sql-concatenacao) tem
custo pior-caso quadrático no tamanho da entrada: dobrar o tamanho da linha
quadruplica o tempo. Uma linha sem quebra de linha de verdade (SVG, bundle
minificado, dado binário disfarçado de texto) pode levar minutos. Como o nome
e o conteúdo do arquivo vêm de um diff possivelmente malicioso, isto é tratado
como defesa, não só como otimização.
"""

import time

from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.scanner import TAMANHO_MAXIMO_LINHA, analisar

# Generoso para não pegar no CI mais lento, mas bem abaixo do que a regex antiga
# levaria numa linha de 50 000 caracteres (~15s).
LIMITE_SEGUNDOS = 2.0


def _linha_sem_sql(tamanho: int) -> str:
    """Linha longa que não deveria casar com nenhuma regra, só ser cara de processar."""
    return "M1 2 L3 4 " * (tamanho // 10)


def test_linha_gigante_nao_trava():
    linha = _linha_sem_sql(50_000)
    assert len(linha) > TAMANHO_MAXIMO_LINHA  # garante que o teste cobre a trava, não o caso normal

    inicio = time.perf_counter()
    achados = analisar([TrechoArquivo(arquivo="a.svg", linhas_adicionadas=[LinhaAdicionada(1, linha)])])
    duracao = time.perf_counter() - inicio

    assert duracao < LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s numa linha de {len(linha)} caracteres"
    assert achados == []  # linha pulada: sem achado, mas também sem travar


def test_linha_gigante_com_sql_e_interpolacao_tambem_nao_trava():
    # Pior caso para a regex antiga: tem "select" e "+"/"${", só que bem longe um do outro.
    linha = "x = " + ("a" * 40_000) + ' + "select name from users"'

    inicio = time.perf_counter()
    analisar([TrechoArquivo(arquivo="a.js", linhas_adicionadas=[LinhaAdicionada(1, linha)])])
    duracao = time.perf_counter() - inicio

    assert duracao < LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s numa linha de {len(linha)} caracteres"


def test_linha_normal_continua_detectando():
    # A trava não pode custar detecção em código real (linha de tamanho normal).
    achados = analisar([TrechoArquivo(arquivo="a.py", linhas_adicionadas=[LinhaAdicionada(1, "h = hashlib.md5(a)")])])
    assert len(achados) == 1
    assert achados[0].regra == "cripto-hash-fraco"


def test_linha_no_limite_exato_ainda_passa_pelas_regras():
    # No limite (não acima dele), a linha deve continuar sendo avaliada normalmente.
    vulneravel = 'h = hashlib.md5(a)  # ' + "x" * (TAMANHO_MAXIMO_LINHA - 24)
    assert len(vulneravel) <= TAMANHO_MAXIMO_LINHA

    achados = analisar([TrechoArquivo(arquivo="a.py", linhas_adicionadas=[LinhaAdicionada(1, vulneravel)])])
    assert any(a.regra == "cripto-hash-fraco" for a in achados)
