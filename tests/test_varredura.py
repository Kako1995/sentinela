import json
from pathlib import Path

import pytest

from typer.testing import CliRunner

from sentinela.cli import app
from sentinela.varredura import (
    MOTIVO_BINARIO,
    MOTIVO_EXCLUIDO,
    MOTIVO_GERADO,
    MOTIVO_GRANDE,
    MOTIVO_LINK,
    MOTIVO_MARKDOWN,
    MOTIVO_PASTA,
    MOTIVO_SVG,
    MOTIVO_TESTE,
    MOTIVO_TRADUCAO,
    TAMANHO_MAXIMO,
    Pulados,
    ler_como_trecho,
    listar_arquivos,
    varrer,
)

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


def test_cli_varrer_le_sentinela_toml_desativa_regra_e_ignora_caminho(tmp_path):
    criar(
        tmp_path,
        {
            "app/db.py": VULNERAVEL,
            "migrations/antiga.py": VULNERAVEL,
            ".sentinela.toml": '[regras]\ndesativar = ["sql-concatenacao"]\n\n[varrer]\nignorar = ["migrations/"]\n',
        },
    )

    r = runner.invoke(app, ["varrer", str(tmp_path), "-f", "json"])

    dados = json.loads(r.stdout)
    assert dados["achados"] == []  # a única regra que pegaria VULNERAVEL está desativada
    assert r.exit_code == 0
    # migrations/ ficou fora da contagem de arquivos analisados (1, não 2)
    assert "1 arquivo(s) analisado(s)." in r.output


def test_cli_varrer_sentinela_toml_invalido_avisa_e_roda_com_padrao(tmp_path):
    criar(tmp_path, {"app/db.py": VULNERAVEL, ".sentinela.toml": "isto não é toml válido [[["})

    r = runner.invoke(app, ["varrer", str(tmp_path), "-f", "json"])

    assert "sintaxe inválida" in r.output
    dados = json.loads(r.stdout)
    assert len(dados["achados"]) == 1  # sem a configuração, a regra continua ativa


# --- menos ruído: Markdown, SVG e build do Next fora por padrão; e dizer o que foi pulado ---


def test_markdown_e_svg_ficam_de_fora_por_padrao(tmp_path):
    criar(tmp_path, {"a.py": "x\n", "README.md": "# oi\n", "docs/guia.mdx": "x", "logo.svg": "<svg/>"})

    assert nomes(tmp_path) == ["a.py"]


def test_incluir_markdown_traz_de_volta_so_o_markdown(tmp_path):
    criar(tmp_path, {"a.py": "x\n", "README.md": "# oi\n", "logo.svg": "<svg/>"})

    assert nomes(tmp_path, incluir_markdown=True) == ["README.md", "a.py"]


def test_arquivo_markdown_passado_direto_e_analisado(tmp_path):
    criar(tmp_path, {"README.md": "# oi\n"})

    assert [t.arquivo for t in varrer(tmp_path / "README.md")] == ["README.md"]


def test_pasta_next_de_build_fica_de_fora_em_qualquer_nivel(tmp_path):
    criar(tmp_path, {"a.py": "x\n", "public/_next/static/chunk.js": "x", "app/_next/y.js": "y"})

    assert nomes(tmp_path) == ["a.py"]


def test_registra_o_que_foi_pulado_e_por_que(tmp_path):
    criar(tmp_path, {
        "ok.py": "x = 1\n",
        "README.md": "# oi\n",
        "docs/guia.mdx": "x",
        "logo.svg": "<svg/>",
        "app.min.js": "x",
        "node_modules/l/a.js": "x",
        "dist/b.js": "x",
        "public/_next/c.js": "x",
        "dado.bin": b"\x00\x01\x02",
        "enorme.txt": "a" * (TAMANHO_MAXIMO + 1),
        "gerado/x.py": "x = 1\n",
        ".sentinela.toml": "[regras]\n",
    })
    (tmp_path / "atalho.py").symlink_to(tmp_path / "ok.py")
    pulados = Pulados()

    trechos = varrer(tmp_path, excluir=["gerado"], pulados=pulados)

    assert [t.arquivo for t in trechos] == ["ok.py"]
    assert sorted(pulados.por_motivo[MOTIVO_MARKDOWN]) == ["README.md", "docs/guia.mdx"]
    assert pulados.por_motivo[MOTIVO_SVG] == ["logo.svg"]
    assert pulados.por_motivo[MOTIVO_GERADO] == ["app.min.js"]
    assert sorted(pulados.por_motivo[MOTIVO_PASTA]) == ["dist", "node_modules", "public/_next"]
    assert pulados.por_motivo[MOTIVO_BINARIO] == ["dado.bin"]
    assert pulados.por_motivo[MOTIVO_GRANDE] == ["enorme.txt"]
    assert pulados.por_motivo[MOTIVO_EXCLUIDO] == ["gerado"]
    assert pulados.por_motivo[MOTIVO_LINK] == ["atalho.py"]
    # a configuração da própria ferramenta não é "algo que o usuário perdeu": não entra na lista
    assert all(".sentinela.toml" not in nomes_ for nomes_ in pulados.por_motivo.values())


def test_incluir_markdown_nao_registra_markdown_como_pulado(tmp_path):
    criar(tmp_path, {"README.md": "# oi\n"})
    pulados = Pulados()

    varrer(tmp_path, incluir_markdown=True, pulados=pulados)

    assert MOTIVO_MARKDOWN not in pulados.por_motivo


def test_cli_varrer_lista_o_que_pulou_e_como_incluir_markdown(tmp_path):
    criar(tmp_path, {"ok.py": "x = 1\n", "README.md": "h = hashlib.md5(senha.encode())\n", "logo.svg": "<svg/>"})

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert "1 arquivo(s) analisado(s)." in r.output
    assert "Pulados" in r.output and "README.md" in r.output and "logo.svg" in r.output
    assert "--incluir-md" in r.output
    assert "criptografia fraca" not in r.output  # o md não foi lido


def test_cli_varrer_incluir_md_le_o_markdown(tmp_path):
    criar(tmp_path, {"ok.py": "x = 1\n", "README.md": "h = hashlib.md5(senha.encode())\n"})

    r = runner.invoke(app, ["varrer", str(tmp_path), "--incluir-md"])

    assert "2 arquivo(s) analisado(s)." in r.output
    assert "criptografia fraca" in r.output and "README.md:1" in r.output


def test_cli_varrer_sem_nada_pulado_nao_imprime_secao_de_pulados(tmp_path):
    criar(tmp_path, {"ok.py": "x = 1\n"})

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert "Pulados" not in r.output


def test_cli_varrer_nomeia_o_arquivo_das_linhas_longas_puladas(tmp_path):
    criar(tmp_path, {"public/bundle.js": "var a = 1;" * 400 + "\n", "ok.py": "x = 1\n"})

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert "public/bundle.js" in r.output and "1 linha(s)" in r.output


def test_cli_varrer_agrupa_pastas_puladas_pelo_nome(tmp_path):
    criar(tmp_path, {
        "ok.py": "x = 1\n",
        "a/__pycache__/x.py": "x",
        "b/c/__pycache__/y.py": "y",
        "d/__pycache__/z.py": "z",
        "node_modules/l/w.js": "w",
    })

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert "pasta de dependências ou build (4):" in r.output  # o total é de pastas, não de nomes
    assert "__pycache__ ×3" in r.output and "node_modules" in r.output
    assert "b/c/__pycache__" not in r.output  # nada de listar caminho por caminho


def test_pastas_de_controle_de_versao_e_editor_nao_entram_no_aviso(tmp_path):
    criar(tmp_path, {"ok.py": "x = 1\n", ".git/config": "[core]\n", ".idea/w.xml": "x", ".vscode/s.json": "{}"})
    pulados = Pulados()

    varrer(tmp_path, pulados=pulados)

    assert pulados.por_motivo == {}
    r = runner.invoke(app, ["varrer", str(tmp_path)])
    assert "Pulados" not in r.output


# --- menos ruído, parte 2: arquivos de TESTE e de TRADUÇÃO ficam de fora por padrão ---


def test_pastas_de_teste_ficam_de_fora_por_padrao(tmp_path):
    criar(tmp_path, {
        "src/a.py": "x\n",
        "tests/t.py": "x\n", "test/u.py": "x\n", "src/__tests__/v.ts": "x\n",
        "src/__mocks__/m.ts": "x\n", "spec/w.rb": "x\n",
    })

    assert nomes(tmp_path) == ["src/a.py"]


@pytest.mark.parametrize("arquivo", [
    "src/a.spec.ts", "src/a.test.js", "src/a.test.tsx", "src/a.spec.mjs", "pkg/test_a.py", "pkg/a_test.py",
    "pkg/conftest.py", "cmd/a_test.go",
])
def test_arquivo_de_teste_e_reconhecido_pelo_nome_em_qualquer_pasta(tmp_path, arquivo):
    criar(tmp_path, {arquivo: "x\n", "src/real.py": "x\n"})

    assert nomes(tmp_path) == ["src/real.py"]


@pytest.mark.parametrize("arquivo", [
    "src/latest.py", "src/contest.py", "src/testing.py", "src/spec.ts", "api/openapi.spec.json", "src/a.testimonial.ts",
    "src/attest.js", "src/protest_data.py",
])
def test_nome_parecido_com_teste_mas_que_nao_e_teste_continua_sendo_lido(tmp_path, arquivo):
    criar(tmp_path, {arquivo: "x\n"})

    assert nomes(tmp_path) == [arquivo]


def test_incluir_testes_traz_de_volta_pastas_e_arquivos_de_teste(tmp_path):
    criar(tmp_path, {"src/a.py": "x\n", "tests/t.py": "x\n", "src/b.spec.ts": "x\n"})

    assert nomes(tmp_path, incluir_testes=True) == ["src/a.py", "src/b.spec.ts", "tests/t.py"]


def test_varrer_uma_pasta_que_ela_mesma_se_chama_tests_le_os_testes(tmp_path):
    """Quem manda varrer `tests/` pediu para ler testes: não faz sentido devolver 0 arquivos analisados."""
    pasta = tmp_path / "tests"
    criar(pasta, {"test_a.py": "x\n", "b.spec.ts": "y\n"})

    assert nomes(pasta) == ["b.spec.ts", "test_a.py"]


def test_arquivo_de_teste_passado_direto_e_analisado(tmp_path):
    criar(tmp_path, {"a.spec.ts": "x\n"})

    assert [t.arquivo for t in varrer(tmp_path / "a.spec.ts")] == ["a.spec.ts"]


def test_arquivos_de_dados_de_traducao_ficam_de_fora_mas_o_codigo_da_pasta_nao(tmp_path):
    criar(tmp_path, {
        "src/app.ts": "x\n",
        "src/i18n/index.ts": "x\n",  # CÓDIGO dentro de i18n continua sendo analisado
        "src/i18n/pt.json": "{}", "src/locales/en.yml": "a: b\n", "translations/de.po": "msgid ''\n",
        "frontend/assets/i18n/th_TH.json": "{}",
        "config/settings.json": "{}",  # JSON fora de pasta de tradução continua sendo lido
    })

    assert nomes(tmp_path) == ["config/settings.json", "src/app.ts", "src/i18n/index.ts"]


def test_incluir_traducoes_traz_de_volta_os_dados(tmp_path):
    criar(tmp_path, {"src/app.ts": "x\n", "src/i18n/pt.json": "{}"})

    assert nomes(tmp_path, incluir_traducoes=True) == ["src/app.ts", "src/i18n/pt.json"]


def test_registra_testes_e_traducoes_como_pulados(tmp_path):
    criar(tmp_path, {
        "ok.py": "x\n", "tests/t.py": "x\n", "src/a.spec.ts": "x\n", "src/i18n/pt.json": "{}", "locales/en.yml": "a: b\n",
    })
    pulados = Pulados()

    varrer(tmp_path, pulados=pulados)

    assert sorted(pulados.por_motivo[MOTIVO_TESTE]) == ["src/a.spec.ts", "tests"]  # a pasta conta 1, os arquivos dela não
    assert sorted(pulados.por_motivo[MOTIVO_TRADUCAO]) == ["locales/en.yml", "src/i18n/pt.json"]


def test_cli_varrer_avisa_de_testes_e_traducoes_e_diz_como_incluir(tmp_path):
    criar(tmp_path, {"ok.py": "x = 1\n", "tests/t.py": VULNERAVEL, "src/i18n/pt.json": '{"password": "palavrasecreta"}'})

    r = runner.invoke(app, ["varrer", str(tmp_path)])

    assert "1 arquivo(s) analisado(s)." in r.output
    assert "teste" in r.output.lower() and "--incluir-testes" in r.output
    assert "tradu" in r.output.lower() and "--incluir-traducoes" in r.output
    assert "SQL injection" not in r.output and "segredo" not in r.output.lower()  # nada do que foi pulado foi lido


def test_cli_varrer_incluir_testes_e_incluir_traducoes_leem_de_volta(tmp_path):
    criar(tmp_path, {"tests/t.py": VULNERAVEL, "src/i18n/pt.json": '{"password": "palavrasecreta"}'})

    r = runner.invoke(app, ["varrer", str(tmp_path), "--incluir-testes", "--incluir-traducoes"])

    assert "2 arquivo(s) analisado(s)." in r.output
    assert "SQL injection" in r.output and "tests/t.py" in r.output
    assert "segredo no código" in r.output
