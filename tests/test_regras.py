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
        ('app.run(host="0.0.0.0", port=5000)', "bind-todas-interfaces"),
        ('app.listen(3000, "0.0.0.0")', "bind-todas-interfaces"),
        ('sock.bind(("0.0.0.0", 9000))', "bind-todas-interfaces"),
        ('host: "0.0.0.0"', "bind-todas-interfaces"),
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
        'app.run(host="127.0.0.1", port=5000)',
        'app.listen(3000, "127.0.0.1")',
        'host: "127.0.0.1"',
        'element.addEventListener("click", handler)',
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


def test_comentario_sentinela_ignore_silencia_so_aquela_linha():
    achados = analisar([trecho(
        "h = hashlib.md5(a)  # sentinela: ignore",
        "h2 = hashlib.md5(b)",
    )])

    assert len(achados) == 1
    assert achados[0].linha == 2


def test_comentario_sentinela_ignore_em_js_e_sem_distinguir_caixa():
    assert analisar([trecho("eval(x)  // Sentinela: Ignore")]) == []


def test_mesma_linha_pode_disparar_regras_diferentes():
    achados = analisar([trecho('os.system("curl " + url); requests.get(url, verify=False)')])

    assert {a.regra for a in achados} == {"injecao-de-comando", "tls-sem-verificacao"}


def test_desativadas_filtra_por_id_da_regra():
    linha = 'os.system("curl " + url); requests.get(url, verify=False)'

    assert analisar([trecho(linha)], desativadas=frozenset({"tls-sem-verificacao"}))[0].regra == "injecao-de-comando"
    assert analisar([trecho(linha)], desativadas=frozenset({"injecao-de-comando", "tls-sem-verificacao"})) == []
    assert analisar([trecho(linha)]) != []  # sem desativadas, continua como sempre (nada muda por padrão)


# ---------- v2: exceções gerais (precisão) sem perder detecções (recall) ----------


@pytest.mark.parametrize(
    "linha, regra",
    [
        ('subprocess.run("convert " + arquivo + " saida.png", shell=True)', "injecao-de-comando"),
        ('subprocess.run(f"convert {arquivo} saida.png", shell=True)', "injecao-de-comando"),
        ('cur.execute("SELECT * FROM pedidos WHERE id = " + str(pedido_id))', "sql-concatenacao"),
        ('lista.innerHTML = "<li>" + termo + "</li>";', "xss-saida-sem-escape"),
        ("<div dangerouslySetInnerHTML={{ __html: perfil.bio }} />", "xss-react-html-perigoso"),
        ("<div dangerouslySetInnerHTML={{ __html: `<p>${comentario}</p>` }} />", "xss-react-html-perigoso"),
        ("<div dangerouslySetInnerHTML={markup} />", "xss-react-html-perigoso"),
    ],
)
def test_v2_continua_pegando_o_vulneravel(linha, regra):
    assert regra in regras_que_casam(linha)


@pytest.mark.parametrize(
    "linha",
    [
        'subprocess.run("make build", shell=True, check=True)',
        'cur.execute("SELECT " + CAMPOS + " FROM t WHERE id = %s", (i,))',
        'cur.execute("DELETE FROM sessoes WHERE expira_em < " + TEMPO_LIMITE)',
        "h = hashlib.md5(url.encode(), usedforsecurity=False)",
        'lista.innerHTML = "<li>Nenhum resultado</li>";',
        "el.innerHTML = `<span class='x'></span>`;",
        'openai_api_key = "env(OPENAI_API_KEY)"',
        'SENHA_ADMIN = "troque-esta-senha"',
        'API_KEY = "sua-chave-aqui"',
        "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
        "<div dangerouslySetInnerHTML={{ __html: `texto fixo` }} />",
    ],
)
def test_v2_nao_dispara_em_codigo_seguro(linha):
    assert regras_que_casam(linha) == set()


def trecho_numerado(*pares: tuple[int, str]) -> TrechoArquivo:
    return TrechoArquivo(arquivo="a.tsx", linhas_adicionadas=[LinhaAdicionada(n, t) for n, t in pares])


def test_janela_html_fixo_em_varias_linhas_nao_dispara():
    achados = analisar([trecho_numerado(
        (1, "<style dangerouslySetInnerHTML={{ __html: `"),
        (2, "  .cartao { color: #333; }"),
        (3, "  .cartao:hover { color: #000; }"),
        (4, "` }} />"),
    )])

    assert achados == []


def test_janela_valor_na_linha_seguinte_e_reportado_na_linha_do_gatilho_uma_vez():
    achados = analisar([trecho_numerado(
        (1, "<div dangerouslySetInnerHTML={{"),
        (2, "  __html: perfil.bio,"),
        (3, "}} />"),
    )])

    assert [(a.regra, a.linha) for a in achados] == [("xss-react-html-perigoso", 1)]


def test_janela_template_com_interpolacao_em_linha_posterior():
    achados = analisar([trecho_numerado(
        (1, "<div dangerouslySetInnerHTML={{ __html: `"),
        (2, "  <p>${comentario}</p>"),
        (3, "` }} />"),
    )])

    assert [a.regra for a in achados] == ["xss-react-html-perigoso"]


def test_janela_nao_junta_linhas_que_nao_sao_vizinhas():
    # Num diff, a linha 2 foi removida: a 1 e a 9 não são vizinhas e não podem ser tratadas como um bloco.
    achados = analisar([trecho_numerado(
        (1, "<div dangerouslySetInnerHTML={{"),
        (9, "  __html: perfil.bio,"),
    )])

    assert achados == []


# --- criptografia fraca: ECB, DES e gerador `random` para segredo ---


@pytest.mark.parametrize(
    "linha, regra",
    [
        ("cipher = AES.new(chave, AES.MODE_ECB)", "cripto-modo-ecb"),
        ("cipher = Cipher(algorithms.AES(chave), modes.ECB())", "cripto-modo-ecb"),
        ("const c = crypto.createCipheriv('aes-256-ecb', chave, null)", "cripto-modo-ecb"),
        ('Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");', "cripto-modo-ecb"),
        ("cipher = DES.new(chave, DES.MODE_CBC, iv)", "cripto-des"),
        ("const c = crypto.createCipheriv('des-cbc', chave, iv)", "cripto-des"),
    ],
)
def test_ecb_e_des_disparam(linha, regra):
    assert regra in regras_que_casam(linha)


@pytest.mark.parametrize(
    "linha",
    [
        "cipher = AES.new(chave, AES.MODE_GCM)",
        "cipher = AES.new(chave, AES.MODE_CTR)",
        "const c = crypto.createCipheriv('aes-256-gcm', chave, iv)",
        "cipher = DES3.new(chave, DES3.MODE_CBC, iv)",  # 3DES é fraco, mas é outra decisão; não é o DES simples
        "descricao = produto.DESCRICAO",
        "const c = crypto.createCipheriv('des3', chave, iv)",
    ],
)
def test_ecb_e_des_nao_disparam_em_modo_seguro(linha):
    assert regras_que_casam(linha) & {"cripto-modo-ecb", "cripto-des"} == set()


@pytest.mark.parametrize(
    "linhas",
    [
        # a palavra de segredo na linha de cima, o sorteio na de baixo (janela)
        ["def gerar_token_reset():", '    return "".join(random.choice(string.ascii_letters) for _ in range(32))'],
        ["senha_temporaria = ''.join(random.choices(string.ascii_letters + string.digits, k=10))"],
        ["session_id = random.getrandbits(128)"],
        ["const token = Math.random().toString(36).slice(2)"],
        ["const resetCode = Math.random().toString(16).substring(2, 10)"],
    ],
)
def test_random_para_segredo_dispara(linhas):
    achados = analisar([trecho(*linhas)])

    assert [a.regra for a in achados] == ["cripto-random-token"]
    assert achados[0].cwe == "CWE-338"
    assert achados[0].linha == 1  # a linha em que a janela começa, sem repetir nas seguintes


@pytest.mark.parametrize(
    "linhas",
    [
        ["def cor_do_avatar():", "    return random.choice(CORES)"],  # sorteio sem segredo
        ['nome = "".join(random.choice(string.ascii_lowercase) for _ in range(8)) + ".tmp"'],  # alfabeto, mas sem palavra de segredo
        ["const chave = Math.random().toString(36).slice(2)", "return <li key={chave}>{item}</li>"],  # key de React
        ["def sortear_token_do_jogo():", "    return random.choice(FICHAS)"],  # "token" de tabuleiro, sem alfabeto
        ['token = "".join(rng.choice(string.ascii_letters) for _ in range(32))'],  # rng = random.SystemRandom()
        ["import secrets", "token = secrets.token_urlsafe(32)"],
        ["const token = crypto.randomBytes(32).toString('hex')"],
        ["footprint = random.getrandbits(8)"],  # "otp" dentro de outra palavra
    ],
)
def test_random_sem_segredo_ou_seguro_nao_dispara(linhas):
    assert analisar([trecho(*linhas)]) == []


def test_random_para_segredo_nao_roda_em_arquivo_sem_random():
    # o pré-filtro (gatilho_arquivo) não pode mudar o resultado: sem a palavra, nada a achar de qualquer jeito
    assert analisar([trecho("token = gerar_token()", "senha = pedir_senha()")]) == []
