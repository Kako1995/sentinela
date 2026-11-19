import json
from pathlib import Path

from typer.testing import CliRunner

from sentinela.cli import app

EXEMPLOS = Path(__file__).parent / "exemplos"
runner = CliRunner()

DIFF_SEGURO = "--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n a = 1\n+b = 2\n"
# Só severidade média (hash fraco): não deve falhar o CI.
DIFF_SO_MEDIA = "--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n a = 1\n+h = hashlib.md5(a)\n"


def revisar(*args: str, entrada: str | None = None):
    return runner.invoke(app, ["revisar", *args], input=entrada)


def test_terminal_mostra_achados_mais_graves_primeiro_e_resumo():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"))

    saida = resultado.output
    assert "ALTA" in saida and "MEDIA" in saida
    assert saida.index("ALTA") < saida.index("MEDIA")  # segredo (alta) antes do XSS (media)
    assert "2 achado(s): 1 alta, 1 media." in saida


def test_le_stdin():
    diff = (EXEMPLOS / "simples.diff").read_text(encoding="utf-8")

    resultado = revisar("-", entrada=diff)

    assert "SQL injection" in resultado.output
    assert "app/db.py:14" in resultado.output


def test_exit_code_1_com_severidade_alta_ou_critica():
    assert revisar(str(EXEMPLOS / "simples.diff")).exit_code == 1


def test_exit_code_0_sem_achados():
    resultado = revisar("-", entrada=DIFF_SEGURO)

    assert resultado.exit_code == 0
    assert "Nenhum problema encontrado." in resultado.output


def test_exit_code_0_com_apenas_severidade_media():
    resultado = revisar("-", entrada=DIFF_SO_MEDIA)

    assert "criptografia fraca" in resultado.output
    assert resultado.exit_code == 0


def test_diff_vazio_nao_falha():
    resultado = revisar("-", entrada="")

    assert resultado.exit_code == 0
    assert "Nenhum problema encontrado." in resultado.output


def test_arquivo_inexistente_sai_com_2():
    assert revisar("nao_existe.diff").exit_code == 2


def test_formato_json_e_valido_e_completo():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "json")

    dados = json.loads(resultado.output)  # a saída tem que ser só JSON, para ir num pipe
    assert dados["total"] == 2
    assert [a["severidade"] for a in dados["achados"]] == ["alta", "media"]
    primeiro = dados["achados"][0]
    assert primeiro["arquivo"] == "config.py" and primeiro["linha"] == 2
    assert primeiro["cwe"] == "CWE-798"
    assert resultado.exit_code == 1


def test_formato_json_sem_achados_e_json_valido():
    resultado = revisar("-", "-f", "json", entrada="")

    assert json.loads(resultado.output) == {"total": 0, "achados": []}
    assert resultado.exit_code == 0


def test_formato_markdown_para_comentario_de_pr():
    resultado = revisar(str(EXEMPLOS / "simples.diff"), "--formato", "markdown")

    saida = resultado.output
    assert saida.startswith("<!-- sentinela -->\n## Sentinela")
    assert "### ALTA: SQL injection (CWE-89)" in saida
    assert "`app/db.py:14`" in saida
    assert "**Correção:**" in saida
    assert resultado.exit_code == 1


def test_formato_markdown_sem_achados():
    resultado = revisar("-", "--formato", "markdown", entrada=DIFF_SEGURO)

    assert "Nenhum problema de segurança encontrado" in resultado.output
    assert resultado.exit_code == 0


def test_formato_invalido_e_rejeitado():
    resultado = revisar("-", "--formato", "xml", entrada="")

    assert resultado.exit_code == 2
