import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinela.ast_python import analisar_ast
from sentinela.cli import app
from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.scanner import analisar
from sentinela.varredura import anexar_fontes

runner = CliRunner()


def regras(codigo: str) -> set[str]:
    resultado = analisar_ast("a.py", codigo)
    assert resultado is not None, "o trecho de teste precisa ser Python válido"
    return {a.regra for a in resultado.achados}


# ---------- dado externo -> operação perigosa (taint) ----------


def test_path_traversal_via_variavel_em_outra_linha():
    assert "ast-path-traversal" in regras('''
@app.get("/x")
def x():
    nome = request.args.get("a")
    caminho = os.path.join(PASTA, nome)
    return send_file(caminho)
''')


def test_parametro_de_rota_e_dado_externo():
    assert "ast-path-traversal" in regras('''
@app.get("/a/{nome}")
def ler(nome: str):
    return open("/d/" + nome).read()
''')


def test_depends_nao_e_dado_externo():
    assert regras('''
@app.get("/a")
def ler(pasta=Depends(pasta_do_projeto)):
    return open(pasta).read()
''') == set()


@pytest.mark.parametrize("limpeza", ["secure_filename(request.args['a'])", "os.path.basename(request.args['a'])", "int(request.args['a'])"])
def test_sanitizadores_limpam_o_valor(limpeza):
    assert "ast-path-traversal" not in regras(f'''
@app.get("/x")
def x():
    nome = {limpeza}
    return send_file(os.path.join(PASTA, nome))
''')


def test_validacao_por_lista_de_permitidos_libera_o_uso():
    assert regras('''
@app.get("/x")
def x():
    alvo = request.args["site"]
    if urlparse(alvo).hostname not in PERMITIDOS:
        abort(400)
    return requests.get(alvo).text
''') == set()


def test_ssrf_so_olha_a_url_nao_os_parametros():
    assert regras('requests.get("https://api/x", params={"q": request.args["q"]})\n@app.get("/")\ndef f(): pass') == set()


def test_ssrf_com_url_em_argumento_nomeado():
    assert "ast-ssrf" in regras('''
@app.post("/t")
def t():
    d = request.json["url"]
    return requests.post(url=d, json={}).text
''')


# ---------- só é "externo" em contexto web ----------


def test_request_de_biblioteca_nao_e_dado_de_usuario():
    assert regras('''
def preparar(request):
    return requests.get(request.url)
''') == set()


def test_request_conta_quando_o_arquivo_importa_um_framework_web():
    assert "ast-path-traversal" in regras('''
from django.http import FileResponse

def baixar(request):
    return FileResponse(open("/m/" + request.GET["f"], "rb"))
''')


def test_input_de_script_de_terminal_nao_e_dado_de_atacante():
    assert regras('nome = input("arquivo: ")\nprint(open(nome).read())') == set()


# ---------- SQL em várias linhas ----------


@pytest.mark.parametrize(
    "codigo",
    [
        'sql = ("SELECT * FROM t "\n       "WHERE n = \'" + nome + "\'")\ncur.execute(sql)',
        'sql = """\n SELECT * FROM t\n WHERE n = \'{}\'\n""".format(nome)\ncur.execute(sql)',
        'cur.execute(\n    "SELECT * FROM t "\n    "WHERE n = \'%s\'" % nome\n)',
        'cur.execute(f"SELECT * FROM t WHERE id = {pedido_id}")',
    ],
)
def test_sql_montado_com_valor_variavel(codigo):
    assert "ast-sql-concatenacao" in regras(codigo)


@pytest.mark.parametrize(
    "codigo",
    [
        'sql = ("SELECT * FROM t "\n       "WHERE n = %s")\ncur.execute(sql, (nome,))',
        'cur.execute("SELECT " + CAMPOS + " FROM t WHERE id = %s", (i,))',
        'cur.execute("SELECT * FROM t LIMIT " + str(int(n)))',
        'mensagem = "Falha ao selecionar o item from cache: " + erro',  # texto que parece SQL, mas não vai a um execute
    ],
)
def test_sql_seguro_ou_que_nao_chega_ao_banco(codigo):
    assert "ast-sql-concatenacao" not in regras(codigo)


# ---------- falta de autorização ----------


@pytest.mark.parametrize(
    "codigo",
    [
        '@app.route("/c/<int:i>", methods=["PUT"])\ndef editar(i):\n    db.update(i)',
        '@router.delete("/d/{i}")\ndef apagar(i: int):\n    repo.apagar(i)',
        '@bp.route("/p/<int:i>", methods=["PATCH"])\ndef atualizar(i):\n    db.update(i)',
    ],
)
def test_rota_que_altera_dados_sem_autenticacao_visivel(codigo):
    assert "ast-falta-autorizacao" in regras(codigo)


@pytest.mark.parametrize(
    "codigo",
    [
        '@app.route("/c/<int:i>", methods=["PUT"])\n@login_required\ndef editar(i):\n    db.update(i)',
        '@router.delete("/d/{i}")\ndef apagar(i: int, u=Depends(usuario_atual)):\n    repo.apagar(i)',
        '@router.put("/d/{i}")\ndef atualizar(i: int, quem=Depends(verificar_token)):\n    repo.x(i)',
        '@app.delete("/d/<i>")\ndef apagar(i):\n    if not current_user.is_admin:\n        abort(403)\n    repo.apagar(i)',
        '@app.get("/d/<i>")\ndef ver(i):\n    return repo.ler(i)',  # GET não altera dados
        '@app.post("/login")\ndef entrar():\n    return token()',  # POST costuma ser público (login, cadastro)
    ],
)
def test_rota_com_autenticacao_ou_que_nao_altera_dados(codigo):
    assert "ast-falta-autorizacao" not in regras(codigo)


def test_depends_do_banco_nao_conta_como_autenticacao():
    assert "ast-falta-autorizacao" in regras('@router.delete("/d/{i}")\ndef apagar(i: int, db=Depends(get_db)):\n    db.apagar(i)')


def test_caminho_da_rota_com_a_palavra_permission_nao_conta_como_autenticacao():
    assert "ast-falta-autorizacao" in regras('@app.delete("/permissions/<i>")\ndef apagar(i):\n    repo.apagar(i)')


# ---------- robustez ----------


def test_codigo_que_nao_e_python_valido_devolve_none():
    assert analisar_ast("a.py", "def (:\n") is None


def test_arquivo_muito_aninhado_nao_derruba_a_analise():
    assert analisar_ast("a.py", "x = " + "(" * 400 + "1" + ")" * 400) in (None, analisar_ast("a.py", "x = 1"))


# ---------- integração com o scanner ----------


def trecho(codigo: str, nome: str = "a.py", so_linhas: set[int] | None = None) -> TrechoArquivo:
    linhas = [LinhaAdicionada(i, t) for i, t in enumerate(codigo.splitlines(), start=1)]
    if so_linhas is not None:
        linhas = [l for l in linhas if l.numero in so_linhas]
    return TrechoArquivo(arquivo=nome, linhas_adicionadas=linhas, fonte=codigo)


def test_comentario_sentinela_ignore_silencia_achado_da_ast_tambem():
    codigo = (
        '@app.get("/x")\n'
        "def x():\n"
        '    nome = request.args.get("a")\n'
        "    caminho = os.path.join(PASTA, nome)\n"
        "    return send_file(caminho)  # sentinela: ignore\n"
    )
    assert analisar([trecho(codigo)]) == []


def test_ast_substitui_as_regras_por_linha_de_path_e_ssrf_em_python():
    # A regra por linha dispararia (há `request.` na linha), mas a URL é fixa: a AST sabe que é segura.
    codigo = '@app.get("/c")\ndef c():\n    return requests.get("https://api/x", params={"q": request.args["q"]}).text'

    assert analisar([trecho(codigo)]) == []
    assert analisar([TrechoArquivo("a.py", trecho(codigo).linhas_adicionadas)]) != []  # sem fonte: volta a regra por linha


def test_se_o_arquivo_nao_parseia_as_regras_por_linha_continuam_valendo():
    achados = analisar([trecho('def (:\nos.system("rm " + x)')])

    assert [a.regra for a in achados] == ["injecao-de-comando"]


def test_texto_de_docstring_e_ignorado_pelas_regras_por_linha():
    codigo = 'def f():\n    """Não use eval(x) aqui."""\n    return 1\n'

    assert analisar([trecho(codigo)]) == []


def test_achados_da_ast_so_valem_nas_linhas_adicionadas():
    codigo = '@app.delete("/d/{i}")\ndef apagar(i: int):\n    repo.apagar(i)'

    assert analisar([trecho(codigo, so_linhas={3})]) == []  # a linha do def (2) não foi adicionada
    assert [a.regra for a in analisar([trecho(codigo, so_linhas={1, 2, 3})])] == ["ast-falta-autorizacao"]


def test_regra_por_linha_e_ast_nao_duplicam_o_mesmo_achado():
    codigo = 'def b(cur, nome):\n    cur.execute("SELECT * FROM t WHERE n = \'" + nome + "\'")'

    achados = analisar([trecho(codigo)])

    assert [(a.linha, a.categoria) for a in achados] == [(2, "SQL injection")]


# ---------- --raiz: ler o arquivo completo do disco com segurança ----------

VULN = 'def b(cur, nome):\n    sql = ("SELECT * FROM t "\n           "WHERE n = \'" + nome + "\'")\n    cur.execute(sql)\n'


def trecho_do_diff(arquivo: str, linhas: dict[int, str]) -> TrechoArquivo:
    return TrechoArquivo(arquivo, [LinhaAdicionada(n, t) for n, t in linhas.items()])


def test_anexar_fontes_le_o_arquivo_quando_bate_com_o_diff(tmp_path):
    (tmp_path / "a.py").write_text(VULN)
    t = trecho_do_diff("a.py", {2: '    sql = ("SELECT * FROM t "', 3: '           "WHERE n = \'" + nome + "\'")'})

    assert anexar_fontes([t], tmp_path) == 0
    assert t.fonte == VULN


def test_anexar_fontes_ignora_arquivo_diferente_do_diff(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    t = trecho_do_diff("a.py", {1: "y = 2"})

    assert anexar_fontes([t], tmp_path) == 1
    assert t.fonte is None


def test_anexar_fontes_nao_sai_da_raiz(tmp_path):
    raiz = tmp_path / "repo"
    raiz.mkdir()
    (tmp_path / "segredo.py").write_text("x = 1\n")
    t = trecho_do_diff("../segredo.py", {1: "x = 1"})  # nome malicioso vindo de um diff

    assert anexar_fontes([t], raiz) == 1
    assert t.fonte is None


def test_anexar_fontes_nao_segue_link_simbolico(tmp_path):
    raiz = tmp_path / "repo"
    raiz.mkdir()
    (tmp_path / "fora.py").write_text("x = 1\n")
    (raiz / "a.py").symlink_to(tmp_path / "fora.py")
    t = trecho_do_diff("a.py", {1: "x = 1"})

    assert anexar_fontes([t], raiz) == 1
    assert t.fonte is None


def test_anexar_fontes_rejeita_caminho_absoluto(tmp_path):
    t = trecho_do_diff("/etc/passwd.py", {1: "x"})

    assert anexar_fontes([t], tmp_path) == 1


def test_cli_revisar_com_raiz_pega_o_que_a_linha_sozinha_nao_pega(tmp_path):
    (tmp_path / "a.py").write_text(VULN)
    diff = (
        "diff --git a/a.py b/a.py\n--- /dev/null\n+++ b/a.py\n@@ -0,0 +1,4 @@\n"
        + "".join("+" + l + "\n" for l in VULN.splitlines())
    )

    sem = runner.invoke(app, ["revisar", "-", "-f", "json"], input=diff)
    com = runner.invoke(app, ["revisar", "-", "-f", "json", "--raiz", str(tmp_path)], input=diff)

    assert json.loads(sem.stdout)["total"] == 0  # a consulta está em duas linhas
    assert [a["regra"] for a in json.loads(com.stdout)["achados"]] == ["ast-sql-concatenacao"]
    assert com.exit_code == 1


def test_cli_revisar_raiz_inexistente_sai_com_2(tmp_path):
    r = runner.invoke(app, ["revisar", "-", "--raiz", str(tmp_path / "nao_existe")], input="")

    assert r.exit_code == 2


def test_cli_varrer_usa_a_ast_nos_arquivos_python(tmp_path):
    (tmp_path / "a.py").write_text(VULN)

    r = runner.invoke(app, ["varrer", str(tmp_path), "-f", "json"])

    assert [a["regra"] for a in json.loads(r.stdout)["achados"]] == ["ast-sql-concatenacao"]


# ---------- o mesmo fluxo não aparece duas vezes ----------


def test_path_traversal_em_join_e_send_file_e_reportado_uma_vez_so():
    resultado = analisar_ast("a.py", '''
@app.get("/baixar")
def baixar():
    nome = request.args.get("arquivo")
    caminho = os.path.join(PASTA, nome)
    return send_file(caminho)
''')

    assert [(a.regra, a.linha) for a in resultado.achados] == [("ast-path-traversal", 6)]  # só o send_file


def test_join_sozinho_ainda_e_reportado_quando_nao_ha_operacao_de_arquivo_visivel():
    resultado = analisar_ast("a.py", '''
@app.post("/up")
def up():
    f = request.files["a"]
    f.save(os.path.join(PASTA, f.filename))
''')

    assert [a.regra for a in resultado.achados] == ["ast-path-traversal"]


# ---------- SSRF: clientes HTTP guardados numa variável, e host fixo ----------

CABECALHO_FLASK = "from flask import Flask, request\nimport requests, httpx, aiohttp, urllib3\napp = Flask(__name__)\n"


def _rota(corpo: str, antes: str = "", assincrona: bool = False) -> str:
    return CABECALHO_FLASK + antes + "@app.route('/p')\n" + ("async " if assincrona else "") + "def p():\n    u = request.args.get('url')\n" + corpo


@pytest.mark.parametrize(
    "antes, corpo, assincrona",
    [
        ("s = requests.Session()\n", "    return s.get(u).text", False),  # variável no nível do módulo, usada na rota
        ("", "    s = requests.Session()\n    return s.post(u).text", False),
        ("", "    with httpx.Client() as c:\n        return c.get(u).text", False),
        ("", "    async with httpx.AsyncClient() as c:\n        return (await c.get(u)).text", True),
        ("", "    async with aiohttp.ClientSession() as s:\n        async with s.get(u) as r:\n            return await r.text()", True),
        ("", "    http = urllib3.PoolManager()\n    return http.request('GET', u).data", False),  # a URL é o 2º argumento
        ("", "    c = httpx.AsyncClient()\n    return str(c.request('GET', u))", False),
    ],
)
def test_ssrf_com_cliente_http_guardado_numa_variavel(antes, corpo, assincrona):
    assert "ast-ssrf" in regras(_rota(corpo, antes, assincrona))


@pytest.mark.parametrize(
    "antes, corpo",
    [
        ("", "    cache = {}\n    return str(cache.get(u))"),  # dicionário, não cliente HTTP
        ("from sqlalchemy.orm import Session\n", "    s = Session(engine)\n    return str(s.get(User, u))"),  # Session do SQLAlchemy
        ("", "    s = requests.Session()\n    return s.get('https://api.fixa.net/v1/status').text"),  # URL constante
        ("", "    s = requests.Session()\n    s2 = {}\n    return str(s2.get(u))"),  # outra variável, não a do cliente
        ("", "    sessao = request.args\n    return str(sessao.get(u))"),  # nome parecido, mas não é Session()
    ],
)
def test_get_que_nao_e_cliente_http_nao_e_ssrf(antes, corpo):
    assert "ast-ssrf" not in regras(_rota(corpo, antes))


@pytest.mark.parametrize(
    "corpo",
    [
        "    return requests.get('https://api.fixa.net/v1/' + u).text",
        "    return requests.get(f'https://api.fixa.net/v1/{u}').text",
        "    return requests.get('https://api.fixa.net/v1/%s' % u).text",
        "    return requests.get('https://api.fixa.net/v1/' + u + '/detalhe').text",
        "    return requests.get('http://localhost:8080/x?q=' + u).text",  # host constante, a consulta é do usuário
    ],
)
def test_ssrf_com_host_fixo_no_comeco_da_url_nao_alerta(corpo):
    assert "ast-ssrf" not in regras(_rota(corpo))


@pytest.mark.parametrize(
    "corpo",
    [
        "    return requests.get(f'https://{u}/v1/x').text",  # o host é o dado do usuário
        "    return requests.get('https://' + u).text",
        "    return requests.get(u + '/v1').text",
        "    return requests.get('https://api.fixa.net@' + u).text",  # truque do usuário@host: o prefixo não tem / depois do host
        "    return requests.get('/relativa/' + u).text",  # prefixo que não é um host
    ],
)
def test_ssrf_sem_host_fixo_completo_continua_alertando(corpo):
    assert "ast-ssrf" in regras(_rota(corpo))
