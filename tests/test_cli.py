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


# ---------- --nota ----------


def test_sem_nota_nao_aparece_nada_sobre_nota():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "json")

    assert "nota" not in json.loads(resultado.output)


def test_nota_no_json_com_formula_e_aviso():
    # multiplos.diff: 1 alta (-2) + 1 media (-1) = 10 - 3 = 7.0
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "json", "--nota")

    nota = json.loads(resultado.output)["nota"]
    assert nota["valor"] == 7.0
    assert "crítico tira 3" in nota["formula"]
    assert "não é uma nota de segurança" in nota["aviso"].lower()


def test_nota_no_markdown():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "markdown", "--nota")

    assert "**Nota do Sentinela: 7.0/10**" in resultado.output
    assert "não é uma nota de segurança" in resultado.output.lower()


def test_nota_no_terminal():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--nota")

    assert "Nota do Sentinela: 7.0/10" in resultado.output


def test_nota_sem_achados_e_10():
    resultado = revisar("-", "-f", "json", "--nota", entrada="")

    assert json.loads(resultado.output)["nota"]["valor"] == 10.0


def test_nota_markdown_sem_achados_tambem_mostra():
    resultado = revisar("-", "--formato", "markdown", "--nota", entrada=DIFF_SEGURO)

    assert "**Nota do Sentinela: 10.0/10**" in resultado.output


# ---------- --formato sarif ----------


def test_sarif_e_json_valido_no_schema_2_1_0():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "sarif")

    sarif = json.loads(resultado.output)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert resultado.exit_code == 1  # tem achado alto: mesmo código de saída dos outros formatos


def test_sarif_tem_um_result_por_achado_com_local_e_nivel():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "sarif")

    results = json.loads(resultado.output)["runs"][0]["results"]
    assert len(results) == 2
    alta = next(r for r in results if r["ruleId"] == "segredo-atribuicao")
    assert alta["level"] == "error"  # severidade alta
    assert alta["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config.py"
    assert alta["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    media = next(r for r in results if r["ruleId"] == "xss-saida-sem-escape")
    assert media["level"] == "warning"  # severidade média


def test_sarif_lista_cada_regra_uma_vez_so_nas_rules():
    resultado = revisar(str(EXEMPLOS / "multiplos.diff"), "--formato", "sarif")

    regras = json.loads(resultado.output)["runs"][0]["tool"]["driver"]["rules"]
    assert len(regras) == 2
    assert {r["id"] for r in regras} == {"segredo-atribuicao", "xss-saida-sem-escape"}


def test_sarif_sem_achados_e_valido_e_vazio():
    resultado = revisar("-", "--formato", "sarif", entrada=DIFF_SEGURO)

    sarif = json.loads(resultado.output)
    assert sarif["runs"][0]["results"] == []
    assert resultado.exit_code == 0


def test_sarif_ignora_a_flag_nota():
    resultado = revisar("-", "--formato", "sarif", "--nota", entrada=DIFF_SEGURO)

    assert "nota" not in json.loads(resultado.output)  # SARIF é pra ferramenta, não pra gente ler
