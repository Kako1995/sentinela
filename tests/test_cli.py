from pathlib import Path

from typer.testing import CliRunner

from sentinela.cli import app

EXEMPLOS = Path(__file__).parent / "exemplos"
runner = CliRunner()


def test_revisar_le_arquivo():
    resultado = runner.invoke(app, ["revisar", str(EXEMPLOS / "multiplos.diff")])

    assert resultado.exit_code == 0
    assert "web/views.py: 3 linha(s) adicionada(s)" in resultado.output
    assert "config.py: 1 linha(s) adicionada(s)" in resultado.output


def test_revisar_le_stdin():
    diff = (EXEMPLOS / "simples.diff").read_text(encoding="utf-8")

    resultado = runner.invoke(app, ["revisar", "-"], input=diff)

    assert resultado.exit_code == 0
    assert "app/db.py: 2 linha(s) adicionada(s)" in resultado.output


def test_revisar_arquivo_inexistente():
    resultado = runner.invoke(app, ["revisar", "nao_existe.diff"])

    assert resultado.exit_code == 2


def test_revisar_diff_sem_linhas_adicionadas():
    resultado = runner.invoke(app, ["revisar", "-"], input="")

    assert resultado.exit_code == 0
    assert "Nenhuma linha adicionada" in resultado.output
