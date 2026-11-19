import json
from pathlib import Path

from typer.testing import CliRunner

from sentinela.cli import app
from sentinela.varredura import ler_como_trecho, listar_arquivos, varrer

runner = CliRunner()

VULNERAVEL = 'def buscar(conn, nome):\n    return conn.execute("SELECT * FROM t WHERE n = \'" + nome + "\'")\n'


def criar(raiz: Path, arquivos: dict[str, str | bytes]) -> Path:
    for nome, conteudo in arquivos.items():
        caminho = raiz / nome
        caminho.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(conteudo, bytes):
            caminho.write_bytes(conteudo)
        else:
            caminho.write_text(conteudo, encoding="utf-8")
    return raiz


def nomes(raiz: Path, **kw) -> list[str]:
    return [c.relative_to(raiz).as_posix() for c in listar_arquivos(raiz, **kw)]


def test_varre_arquivos_com_caminho_relativo_e_linhas_numeradas(tmp_path):
    criar(tmp_path, {"app/db.py": VULNERAVEL})

    [trecho] = varrer(tmp_path)

    assert trecho.arquivo == "app/db.py"
    assert [l.numero for l in trecho.linhas_adicionadas] == [1, 2]


def test_pula_pastas_de_dependencias_e_caches(tmp_path):
    criar(tmp_path, {
        "src/a.py": "x = 1\n",
        "node_modules/lib/b.js": "y = 2\n",
        ".venv/lib/c.py": "z = 3\n",
        ".git/config": "[core]\n",
        "src/__pycache__/a.pyc.txt": "cache\n",
    })

    assert nomes(tmp_path) == ["src/a.py"]


def test_pula_lockfiles_e_minificados(tmp_path):
    criar(tmp_path, {"a.py": "x\n", "package-lock.json": "{}", "app.min.js": "x", "poetry.lock": "x"})

    assert nomes(tmp_path) == ["a.py"]


def test_excluir_por_pasta_glob_e_nome(tmp_path):
    criar(tmp_path, {
        "src/a.py": "x\n", "tests/t.py": "x\n", "docs/guia.md": "x\n", "src/gerado_pb2.py": "x\n",
    })

    restantes = nomes(tmp_path, excluir=["tests", "docs/*", "*_pb2.py"])

    assert restantes == ["src/a.py"]


def test_excluir_nao_pega_pastas_so_com_nome_parecido(tmp_path):
    criar(tmp_path, {"tests_extras/a.py": "x\n", "tests/b.py": "x\n"})

    assert nomes(tmp_path, excluir=["tests"]) == ["tests_extras/a.py"]


def test_binarios_grandes_e_ilegiveis_sao_ignorados(tmp_path):
    criar(tmp_path, {
        "ok.py": "x = 1\n",
        "imagem.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00binario",
        "latin1.txt": "caf\xe9".encode("latin-1"),
    })
    (tmp_path / "enorme.txt").write_text("a" * 1_000_001)

    assert [t.arquivo for t in varrer(tmp_path)] == ["ok.py"]


def test_links_simbolicos_nao_sao_seguidos(tmp_path):
    fora = tmp_path / "fora"
    projeto = tmp_path / "projeto"
    criar(fora, {"segredo.py": "x\n"})
    criar(projeto, {"a.py": "x\n"})
    (projeto / "atalho.py").symlink_to(fora / "segredo.py")

    assert nomes(projeto) == ["a.py"]


def test_aceita_um_arquivo_unico(tmp_path):
    criar(tmp_path, {"a.py": VULNERAVEL})

    [trecho] = varrer(tmp_path / "a.py")

    assert trecho.arquivo == "a.py"


def test_ler_como_trecho_devolve_none_para_binario(tmp_path):
    criar(tmp_path, {"b.bin": b"\x00\x01\x02"})

    assert ler_como_trecho(tmp_path / "b.bin", tmp_path) is None


def test_cli_varrer_acha_vulnerabilidade_e_sai_com_1(tmp_path):
    criar(tmp_path, {"app/db.py": VULNERAVEL, "ok.py": "x = 1\n"})

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert r.exit_code == 1
    assert "SQL injection" in r.output and "app/db.py:2" in r.output
    assert "2 arquivo(s) analisado(s)." in r.output


def test_cli_varrer_projeto_limpo_sai_com_0(tmp_path):
    criar(tmp_path, {"ok.py": "x = 1\n"})

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert r.exit_code == 0 and "Nenhum problema encontrado." in r.output


def test_cli_varrer_excluir_repetido(tmp_path):
    criar(tmp_path, {"app/db.py": VULNERAVEL, "tests/t.py": VULNERAVEL, "docs/d.py": VULNERAVEL})

    r = runner.invoke(app, ["varrer", str(tmp_path), "-f", "json", "-x", "tests", "-x", "docs"])

    dados = json.loads(r.stdout)  # o aviso de contagem vai para stderr; stdout é só JSON
    assert [a["arquivo"] for a in dados["achados"]] == ["app/db.py"]


def test_cli_varrer_caminho_inexistente_sai_com_2(tmp_path):
    r = runner.invoke(app, ["varrer", str(tmp_path / "nao_existe")])

    assert r.exit_code == 2
