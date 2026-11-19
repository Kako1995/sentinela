from pathlib import Path

from sentinela.diff import parse_diff

EXEMPLOS = Path(__file__).parent / "exemplos"


def ler(nome: str) -> str:
    return (EXEMPLOS / nome).read_text(encoding="utf-8")


def test_diff_simples_guarda_arquivo_e_numero_da_linha():
    trechos = parse_diff(ler("simples.diff"))

    assert [t.arquivo for t in trechos] == ["app/db.py"]
    adicionadas = trechos[0].linhas_adicionadas
    # O hunk começa na linha 10 do arquivo novo; 2 linhas de contexto, depois as adicionadas.
    assert [l.numero for l in adicionadas] == [13, 14]
    assert "SELECT * FROM users" in adicionadas[1].texto


def test_varios_arquivos_sao_separados_e_removidos_ignorados():
    trechos = parse_diff(ler("multiplos.diff"))

    assert [t.arquivo for t in trechos] == ["web/views.py", "config.py"]


def test_varios_hunks_no_mesmo_arquivo():
    views = parse_diff(ler("multiplos.diff"))[0]

    # Hunk 1: linha 2. Hunk 2 começa na 21: contexto na 21, "-" não conta, adicionadas na 22 e 23.
    assert [l.numero for l in views.linhas_adicionadas] == [2, 22, 23]


def test_arquivo_novo_com_aviso_de_sem_newline():
    trechos = parse_diff(ler("novo_arquivo.diff"))

    assert [t.arquivo for t in trechos] == ["upload.py"]
    assert [l.numero for l in trechos[0].linhas_adicionadas] == [1, 2, 3, 4]


def test_patch_de_cada_arquivo_nao_vaza_para_o_outro():
    views, config = parse_diff(ler("multiplos.diff"))

    assert "API_KEY" in config.patch and "API_KEY" not in views.patch
    assert "import os" in views.patch and "import os" not in config.patch


def test_linha_adicionada_que_comeca_com_dois_sinais_nao_vira_cabecalho():
    diff = (
        "--- a/x.txt\n+++ b/x.txt\n@@ -1,1 +1,2 @@\n"
        " antes\n+++ parece cabecalho\n"
    )
    trechos = parse_diff(diff)

    assert [t.arquivo for t in trechos] == ["x.txt"]
    assert trechos[0].linhas_adicionadas[0].texto == "++ parece cabecalho"


def test_diff_u_sem_diff_git_separa_arquivos():
    diff = (
        "--- a/um.py\n+++ b/um.py\n@@ -1 +1,2 @@\n x\n+y\n"
        "--- a/dois.py\n+++ b/dois.py\n@@ -1 +1,2 @@\n a\n+b\n"
    )
    trechos = parse_diff(diff)

    assert [t.arquivo for t in trechos] == ["um.py", "dois.py"]


def test_texto_vazio_ou_sem_diff():
    assert parse_diff("") == []
    assert parse_diff("isto não é um diff\n") == []
