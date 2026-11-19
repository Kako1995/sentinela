from pathlib import Path

from typer.testing import CliRunner

from sentinela.cli import app

EXEMPLOS = Path(__file__).parent / "exemplos"
runner = CliRunner()


def test_revisar_le_arquivo():
    resultado = runner.invoke(app, ["revisar", str(EXEMPLOS / "multiplos.diff")])

    assert resultado.exit_code == 0
    assert "web/views.py:22 [media] XSS" in resultado.output
    assert "config.py:2 [alta] segredo no código" in resultado.output
    assert "2 achado(s)." in resultado.output


def test_revisar_le_stdin():
    diff = (EXEMPLOS / "simples.diff").read_text(encoding="utf-8")

    resultado = runner.invoke(app, ["revisar", "-"], input=diff)

    assert resultado.exit_code == 0
    assert "app/db.py:14 [alta] SQL injection (sql-concatenacao, CWE-89)" in resultado.output
    assert "Correção:" in resultado.output


def test_revisar_diff_sem_problemas():
    diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n a = 1\n+b = 2\n"

    resultado = runner.invoke(app, ["revisar", "-"], input=diff)

    assert resultado.exit_code == 0
    assert "Nenhum problema encontrado." in resultado.output


def test_revisar_arquivo_inexistente():
    resultado = runner.invoke(app, ["revisar", "nao_existe.diff"])

    assert resultado.exit_code == 2


def test_revisar_diff_sem_linhas_adicionadas():
    resultado = runner.invoke(app, ["revisar", "-"], input="")

    assert resultado.exit_code == 0
    assert "Nenhuma linha adicionada" in resultado.output
