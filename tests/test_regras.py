import pytest

from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.models import Severity
from sentinela.regras import REGRAS
from sentinela.scanner import analisar


def regras_que_casam(linha: str) -> set[str]:
    return {r.id for r in REGRAS if r.casa(linha)}


@pytest.mark.parametrize(
    "linha, regra",
    [
        ('conn.execute("SELECT * FROM users WHERE name = \'" + nome + "\'")', "sql-concatenacao"),
        ('q = f"DELETE FROM t WHERE id = {id}"', "sql-concatenacao"),
        ('db.query(`SELECT * FROM users WHERE id = ${id}`)', "sql-concatenacao"),
        ('cur.execute("UPDATE t SET a = %s WHERE b = %d" % (a, b))', "sql-concatenacao"),
        ('API_KEY = "sk-live-123456"', "segredo-atribuicao"),
        ('password: "hunter2hunter2"', "segredo-atribuicao"),
        ('aws = "AKIAIOSFODNN7EXAMPLE"', "segredo-formato-conhecido"),
        ("-----BEGIN RSA PRIVATE KEY-----", "segredo-formato-conhecido"),
        ('html = "<h1>" + nome + "</h1>"', "xss-saida-sem-escape"),
        ('return f"<p>{comentario}</p>"', "xss-saida-sem-escape"),
        ("el.innerHTML = valor", "xss-saida-sem-escape"),
        ("{{ comentario|safe }}", "xss-saida-sem-escape"),
        ('open(os.path.join("/up", request.args["f"]))', "path-traversal-entrada"),
        ("fs.readFile(req.query.nome, cb)", "path-traversal-entrada"),
        ("dados = pickle.loads(corpo)", "desserializacao-insegura"),
        ("cfg = yaml.load(texto)", "desserializacao-insegura"),
        ('r = requests.get(request.args["url"])', "ssrf-url-da-entrada"),
        ("os.system('ls ' + pasta)", "injecao-de-comando"),
        ("subprocess.run(cmd, shell=True)", "injecao-de-comando"),
        ("resultado = eval(expressao)", "injecao-de-comando"),
        ("h = hashlib.md5(senha.encode())", "cripto-hash-fraco"),
        ("requests.get(url, verify=False)", "tls-sem-verificacao"),
    ],
)
def test_regra_pega_codigo_vulneravel(linha, regra):
    assert regra in regras_que_casam(linha)


@pytest.mark.parametrize(
    "linha",
    [
        'conn.execute("SELECT * FROM users WHERE name = ?", (nome,))',
        'cur.execute("UPDATE t SET a = %s WHERE b = %s", (a, b))',
        'API_KEY = os.environ["API_KEY"]',
        'API_KEY = "changeme-please"',
        'password = "<sua-senha-aqui>"',
        "el.textContent = valor",
        'el.innerHTML = ""',
        'html = "<h1>" + escape(nome) + "</h1>"',
        "dados = json.loads(corpo)",
        "cfg = yaml.safe_load(texto)",
        "cfg = yaml.load(texto, Loader=yaml.SafeLoader)",
        'resultado = eval("1 + 1")',
        "h = hashlib.sha256(dados)",
        "requests.get(url, timeout=5)",
        'subprocess.run(["ls", pasta])',
        'texto = "selecione todos os itens da lista"',
    ],
)
def test_regra_nao_dispara_em_codigo_seguro(linha):
    assert regras_que_casam(linha) == set()


def trecho(*textos: str) -> TrechoArquivo:
    return TrechoArquivo(
        arquivo="a.py",
        linhas_adicionadas=[LinhaAdicionada(i + 1, t) for i, t in enumerate(textos)],
    )


def test_scanner_preenche_finding_com_linha_e_regra():
    achados = analisar([trecho("x = 1", "h = hashlib.md5(a)")])

    assert len(achados) == 1
    assert (achados[0].arquivo, achados[0].linha) == ("a.py", 2)
    assert achados[0].regra == "cripto-hash-fraco"
    assert achados[0].cwe == "CWE-327"
    assert achados[0].severidade is Severity.media


def test_scanner_ignora_comentarios():
    assert analisar([trecho("# h = hashlib.md5(a)", "// eval(x)", " * pickle.loads(x)")]) == []


def test_mesma_linha_pode_disparar_regras_diferentes():
    achados = analisar([trecho('os.system("curl " + url); requests.get(url, verify=False)')])

    assert {a.regra for a in achados} == {"injecao-de-comando", "tls-sem-verificacao"}
