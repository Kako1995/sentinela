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


def test_isencao_de_innerhtml_numerico_nao_trava_perto_do_limite():
    """As exceções novas (template só com número) não podem ter custo explosivo: uma linha quase no
    limite que NÃO casa a isenção (último ${} não é número) é o pior caso do backtracking."""
    corpo = "${n.toFixed(1)}" * 120  # ~1800 caracteres, abaixo de TAMANHO_MAXIMO_LINHA
    linha = "el.innerHTML = `" + corpo + "${usuario.nome}`"
    assert len(linha) < TAMANHO_MAXIMO_LINHA

    inicio = time.perf_counter()
    achados = analisar([TrechoArquivo(arquivo="a.js", linhas_adicionadas=[LinhaAdicionada(1, linha)])])
    duracao = time.perf_counter() - inicio

    assert duracao < LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s"
    assert [a.regra for a in achados] == ["xss-saida-sem-escape"]  # e ainda alerta, porque tem dado variável


def test_regra_de_senha_curta_nao_trava_com_muitas_ocorrencias_na_mesma_linha():
    linha = "senha='abcdef" * 150  # sem aspa de fechamento: a regra tenta (e desiste de) cada ocorrência
    assert len(linha) < TAMANHO_MAXIMO_LINHA

    inicio = time.perf_counter()
    analisar([TrechoArquivo(arquivo="a.js", linhas_adicionadas=[LinhaAdicionada(1, linha)])])
    duracao = time.perf_counter() - inicio

    assert duracao < LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s"


def test_regra_de_ssrf_por_prefixo_nao_trava_com_muitos_enderecos_na_mesma_linha():
    """A regra procura dois endereços na mesma linha com `[^\\n]{0,100}?` no meio: o pior caso é uma linha
    cheia de candidatos que nunca fecha o par."""
    linha = "x = ['10.', '" + "10.5', '" * 180  # vários "10." seguidos de decimais, perto do limite de tamanho
    assert len(linha) < TAMANHO_MAXIMO_LINHA

    inicio = time.perf_counter()
    analisar([TrechoArquivo(arquivo="a.js", linhas_adicionadas=[LinhaAdicionada(1, linha)])])
    duracao = time.perf_counter() - inicio

    assert duracao < LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s"


def test_isencao_por_arquivo_do_cloudflare_access_nao_trava_em_arquivo_grande():
    """A isenção usa lookahead com `.*` sobre o arquivo inteiro: o pior caso é um arquivo grande que menciona o
    cabeçalho de e-mail, tem muitos 'cf-access-jwt' soltos e nenhuma verificação."""
    corpo = "x = 1  # cf-access-jwt-assertion\n" * 25_000  # ~800 KB, abaixo do TAMANHO_MAXIMO de arquivo
    linhas = ["email = req.headers.get('cf-access-authenticated-user-email')"] + corpo.splitlines()
    trecho = TrechoArquivo(
        arquivo="a.py",
        linhas_adicionadas=[LinhaAdicionada(i + 1, t) for i, t in enumerate(linhas)],
        fonte="\n".join(linhas),
    )

    inicio = time.perf_counter()
    achados = analisar([trecho])
    duracao = time.perf_counter() - inicio

    assert duracao < 5 * LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s num arquivo de {len(trecho.fonte)} caracteres"
    assert [a.regra for a in achados if a.regra == "cloudflare-access-sem-jwt"] == ["cloudflare-access-sem-jwt"]


def test_tag_sql_com_generico_nao_trava_com_muitos_sql_na_mesma_linha():
    """O genérico opcional da tag (`sql<...>`) varre até o fim da linha para achar o `>` e a crase: com muitos `sql<`
    sem fechar, o pior caso é quadrático no tamanho da linha, que tem teto (TAMANHO_MAXIMO_LINHA)."""
    linha = "x = " + "sql<" * 450  # perto do limite, nunca fecha nem tem crase
    assert len(linha) < TAMANHO_MAXIMO_LINHA

    inicio = time.perf_counter()
    analisar([TrechoArquivo(arquivo="a.ts", linhas_adicionadas=[LinhaAdicionada(1, linha + " SELECT FROM ${x}")])])
    duracao = time.perf_counter() - inicio

    assert duracao < LIMITE_SEGUNDOS, f"demorou {duracao:.2f}s"
