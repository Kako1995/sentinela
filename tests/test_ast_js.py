import json

import pytest
from typer.testing import CliRunner

from sentinela import ast_js
from sentinela.ast_js import analisar_ast_js
from sentinela.cli import app
from sentinela.diff import LinhaAdicionada, TrechoArquivo
from sentinela.scanner import analisar
from sentinela.varredura import anexar_fontes

runner = CliRunner()


def regras(codigo: str, arquivo: str = "a.js") -> set[str]:
    resultado = analisar_ast_js(arquivo, codigo)
    assert resultado is not None
    return {a.regra for a in resultado.achados}


# ---------- caminho de arquivo ----------


@pytest.mark.parametrize(
    "codigo, arquivo",
    [
        ("app.get('/d', (req, res) => {\n const n = req.query.a;\n const c = path.join(DIR, n);\n res.sendFile(c);\n});", "a.js"),
        ("app.get('/f/:n', (req, res) => res.sendFile(path.resolve('./p', req.params.n)));", "a.js"),
        ("export async function GET(request, { params }) {\n return fs.promises.readFile(`./u/${params.nome}`)\n}", "app/api/x/route.ts"),
        ("'use server'\nexport async function ler(nome: string) { return fs.readFile('/d/' + nome) }", "a.ts"),
        ("app.get('/a', (req, res) => { res.send(readFileSync('./d/' + req.query.f)) })", "a.js"),  # *Sync sem import
        ("'use server'\nexport async function e(f: FormData) {\n const n = f.get('a') as string\n await fs.writeFile(`./u/${n}`, 'x')\n}", "a.ts"),
    ],
)
def test_path_traversal_com_dado_externo(codigo, arquivo):
    assert "ast-path-traversal" in regras(codigo, arquivo)


@pytest.mark.parametrize(
    "codigo",
    [
        "app.get('/d', (req, res) => res.sendFile(path.join(DIR, path.basename(req.query.f))));",
        "app.get('/n/:d', async (req, res) => { const d = Number(req.params.d); res.send(await fs.promises.readFile(`./l/${d}.txt`)) });",
        "app.get('/t/:n', (req, res) => {\n const { n } = req.params;\n if (!TEMAS.includes(n)) return res.status(404).end();\n res.sendFile(path.join(P, n));\n});",
        "app.get('/a/:id', async (req, res) => {\n const { id } = req.params;\n if (!/^[a-z0-9-]+$/i.test(id)) { return res.status(400).send('x'); }\n res.send(await fs.promises.readFile(`./d/${id}.json`));\n});",
        "const c = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));",
    ],
)
def test_path_seguro(codigo):
    assert "ast-path-traversal" not in regras(codigo)


# ---------- SSRF ----------


@pytest.mark.parametrize(
    "codigo, arquivo",
    [
        ("export async function POST(request) {\n const { url } = await request.json()\n return fetch(url)\n}", "app/api/x/route.ts"),
        ("router.get('/p', async (req, res) => { const a = req.query.url; const r = await axios.get(a); res.json(r.data) });", "a.js"),
        ("app.post('/c', (req, res) => { https.get(req.body.url, (r) => res.sendStatus(r.statusCode)) });", "a.js"),
        ("app.get('/c', async (req, res) => { await axios({ method: 'get', url: req.query.u }) });", "a.js"),
    ],
)
def test_ssrf_com_url_do_usuario(codigo, arquivo):
    assert "ast-ssrf" in regras(codigo, arquivo)


@pytest.mark.parametrize(
    "codigo",
    [
        "app.get('/c', async (req, res) => { await fetch('https://api.x.com/v1?c=' + encodeURIComponent(req.query.c)) });",
        "app.get('/c', async (req, res) => { await fetch(`https://api.x.com/c/${encodeURIComponent(req.query.c)}`) });",
        "app.get('/c', async (req, res) => { await fetch(`https://api.x.com/c/${req.query.c}`) });",  # host fixo antes do /
        "app.get('/p', async (req, res) => {\n const a = req.query.url;\n if (!HOSTS.has(new URL(a).hostname)) return res.status(400).end();\n await fetch(a);\n});",
    ],
)
def test_ssrf_seguro_host_fixo_ou_validado(codigo):
    assert "ast-ssrf" not in regras(codigo)


def test_ssrf_template_em_que_o_dado_controla_o_host_e_perigoso():
    assert "ast-ssrf" in regras("app.get('/c', async (req, res) => { await fetch(`https://${req.query.host}/x`) });")


# ---------- SQL ----------


@pytest.mark.parametrize(
    "codigo",
    [
        "app.get('/c', async (req, res) => {\n const { cidade } = req.query;\n const sql = `\n  SELECT id FROM c\n  WHERE cidade = '${cidade}'\n `;\n await db.query(sql);\n});",
        "app.get('/p/:id', (req, res) => {\n const q = \"SELECT * FROM p \" +\n  \"WHERE c = '\" + req.params.id + \"'\";\n db.execute(q);\n});",
        "await pool.query(`SELECT * FROM u WHERE n = '${nome}'`);",
        "await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE id = ${id}`);",
    ],
)
def test_sql_montado_como_texto(codigo):
    assert "ast-sql-concatenacao" in regras(codigo)


@pytest.mark.parametrize(
    "codigo",
    [
        "await pool.query('SELECT * FROM u WHERE n = $1', [nome]);",
        "await client.query({ text: 'SELECT * FROM t WHERE id = $1', values: [id] });",
        "const r = await sql`SELECT * FROM u WHERE n = ${nome}`;",
        "const r = await prisma.$queryRaw`SELECT * FROM u WHERE e = ${email}`;",
        "await db.query(`SELECT * FROM ${TABELA} WHERE ativo = true`);",
        "await db.query(`SELECT * FROM t LIMIT ${Number(n)}`);",
        "console.log(`Falha ao selecionar item from cache: ${erro}`);",  # parece SQL, mas não vai a um query()
    ],
)
def test_sql_seguro(codigo):
    assert "ast-sql-concatenacao" not in regras(codigo)


def test_filtro_do_supabase_com_dado_do_usuario():
    codigo = "export async function POST(request) {\n const { t } = await request.json()\n return supabase.from('p').select('*').or(`nome.ilike.%${t}%`)\n}"

    assert "ast-filtro-postgrest" in regras(codigo, "app/api/x/route.ts")
    assert "ast-filtro-postgrest" not in regras("supabase.from('c').select('*').or('status.eq.ativa,status.eq.pendente')")


# ---------- comando e HTML na resposta ----------


def test_exec_com_dado_do_usuario_mas_nao_execfile():
    assert "ast-injecao-de-comando" in regras("app.post('/c', (req, res) => { exec(`convert ${req.body.f} s.png`, cb) });")
    assert "ast-injecao-de-comando" in regras("app.get('/l', (req, res) => { res.send(execSync('git log ' + req.query.b)) });")
    assert "ast-injecao-de-comando" not in regras("app.post('/c', (req, res) => { execFile('convert', [req.body.f, 's.png'], cb) });")


@pytest.mark.parametrize(
    "codigo",
    [
        "app.get('/b', (req, res) => { const t = req.query.q; res.send(`<h1>Resultados para ${t}</h1>`); });",
        "app.post('/r', (req, res) => { res.send('<p>' + req.body.msg + '</p>'); });",
        "app.get('/b', (req, res) => { res.send(req.query.q); });",
    ],
)
def test_xss_refletido(codigo):
    assert "ast-xss-resposta" in regras(codigo)


@pytest.mark.parametrize(
    "codigo",
    [
        "app.get('/b', (req, res) => { res.json({ termo: req.query.q }); });",
        "app.get('/b', (req, res) => { const t = escapeHtml(req.query.q); res.send(`<h1>${t}</h1>`); });",
        "app.get('/n', (req, res) => { res.send(`<p>Total: ${Number(req.query.n)}</p>`); });",
    ],
)
def test_xss_seguro(codigo):
    assert "ast-xss-resposta" not in regras(codigo)


# ---------- falta de autorização ----------


@pytest.mark.parametrize(
    "codigo, arquivo",
    [
        ("app.delete('/u/:id', async (req, res) => { await U.destroy({ where: { id: req.params.id } }); res.sendStatus(204); });", "a.js"),
        ("router.patch('/p/:id', async (req, res) => { await P.update(req.body); res.sendStatus(204); });", "a.js"),
        ("export async function DELETE(request, { params }) {\n await db.doc.delete({ where: { id: params.id } })\n return new Response(null)\n}", "app/api/d/route.ts"),
        ("'use server'\nexport async function apagarPaciente(id: string) { await db.paciente.delete({ where: { id } }) }", "a.ts"),
        ("'use server'\nexport async function atualizarConsulta(id: string, d: any) { await db.c.update({ where: { id }, data: d }) }", "a.ts"),
    ],
)
def test_rota_ou_action_sem_autenticacao_visivel(codigo, arquivo):
    assert {"ast-falta-autorizacao", "ast-falta-autorizacao-action"} & regras(codigo, arquivo)


@pytest.mark.parametrize(
    "codigo, arquivo",
    [
        ("app.delete('/u/:id', requireAuth, async (req, res) => { await U.destroy(); });", "a.js"),
        ("router.use(authenticate);\nrouter.delete('/d/:id', async (req, res) => { await D.destroy(); });", "a.js"),
        ("router.delete('/x/:id', passport.authenticate('jwt'), async (req, res) => { await X.destroy(); });", "a.js"),
        ("app.get('/u/:id', async (req, res) => { res.json(await U.find(req.params.id)); });", "a.js"),  # GET
        ("app.delete('/u/:id', controller.remove);", "a.js"),  # handler que não dá para ver
        ("export async function DELETE(request, { params }) {\n const session = await auth()\n if (!session) return new Response('x', { status: 401 })\n await db.d.delete()\n}", "app/api/d/route.ts"),
        ("'use server'\nexport async function apagar(id: string) {\n const s = await createClient()\n const { data: { user } } = await s.auth.getUser()\n if (!user) throw new Error('x')\n}", "a.ts"),
        ("'use server'\nexport async function validarToken(token: string) { return db.convite.findFirst({ where: { token } }) }", "a.ts"),  # só lê
    ],
)
def test_rota_ou_action_com_autenticacao_ou_que_nao_altera(codigo, arquivo):
    assert not ({"ast-falta-autorizacao", "ast-falta-autorizacao-action"} & regras(codigo, arquivo))


@pytest.mark.parametrize("helper", ["requireMaster", "requireCurrentClinic", "assertAdmin", "ensureLoggedIn"])
def test_helpers_require_assert_ensure_contam_como_autenticacao(helper):
    codigo = f"'use server'\nexport async function removerAdmin(id: string) {{\n await {helper}()\n await db.admin.delete({{ where: {{ id }} }})\n}}"

    assert "ast-falta-autorizacao-action" not in regras(codigo, "a.ts")


@pytest.mark.parametrize("nao_helper", ["requestInvoice(id)", "const required = ['id']"])
def test_request_e_required_nao_contam_como_autenticacao(nao_helper):
    codigo = f"'use server'\nexport async function cancelarPedido(id: string) {{\n {nao_helper}\n await db.pedido.update({{ where: {{ id }} }})\n}}"

    assert "ast-falta-autorizacao-action" in regras(codigo, "a.ts")


# ---------- só é dado externo em contexto web ----------


def test_request_de_biblioteca_nao_e_dado_de_usuario():
    assert regras("function enviar(request) { return fetch(request.url, { method: request.method }); }") == set()


def test_parametro_de_funcao_comum_nao_e_dado_externo():
    assert regras("function lerConfig(caminho) { return JSON.parse(fs.readFileSync(caminho, 'utf8')); }") == set()


def test_arquivo_sem_diretiva_nao_trata_parametros_como_externos():
    assert "ast-path-traversal" not in regras("export async function ler(nome) { return fs.readFile('/d/' + nome) }", "a.ts")


# ---------- parser ----------


def test_tsx_com_jsx_e_tipos_e_analisado():
    codigo = "export default async function Page({ searchParams }: { searchParams: { f: string } }) {\n const t = readFileSync('./d/' + searchParams.f, 'utf8')\n return <pre>{t}</pre>\n}"

    assert "ast-path-traversal" in regras(codigo, "app/docs/page.tsx")


def test_extensao_que_nao_e_js_devolve_none():
    assert analisar_ast_js("a.rb", "puts 1") is None


def test_sem_tree_sitter_devolve_none_e_o_resto_continua(monkeypatch):
    monkeypatch.setattr(ast_js, "_DISPONIVEL", False)

    assert analisar_ast_js("a.js", "app.get('/', (req, res) => res.send(req.query.q))") is None


# ---------- integração com o scanner, a varredura e o --raiz ----------


def trecho(codigo: str, nome: str, fonte: bool = True) -> TrechoArquivo:
    linhas = [LinhaAdicionada(i, t) for i, t in enumerate(codigo.splitlines(), start=1)]
    return TrechoArquivo(arquivo=nome, linhas_adicionadas=linhas, fonte=codigo if fonte else None)


def test_ast_de_js_substitui_as_regras_por_linha_de_path_e_ssrf():
    # A regra por linha dispararia (há `req.` na linha), mas a URL tem host fixo: a AST sabe que é segura.
    codigo = "app.get('/c', async (req, res) => { await fetch('https://api.x.com/v1?c=' + encodeURIComponent(req.query.c)); });"

    assert analisar([trecho(codigo, "a.js")]) == []
    assert [a.regra for a in analisar([trecho(codigo, "a.js", fonte=False)])] == ["ssrf-url-da-entrada"]


def test_achado_so_vale_nas_linhas_adicionadas():
    codigo = "app.get('/b', (req, res) => {\n  const t = req.query.q;\n  res.send(`<h1>${t}</h1>`);\n});"
    t = trecho(codigo, "a.js")
    t.linhas_adicionadas = [l for l in t.linhas_adicionadas if l.numero != 3]

    assert analisar([t]) == []


def test_varrer_analisa_typescript(tmp_path):
    (tmp_path / "route.ts").write_text("export async function DELETE(request, { params }) {\n await db.d.delete({ where: { id: params.id } })\n}\n")

    r = runner.invoke(app, ["varrer", str(tmp_path), "-f", "json"])

    assert [a["regra"] for a in json.loads(r.stdout)["achados"]] == ["ast-falta-autorizacao"]


def test_anexar_fontes_le_typescript_e_confere_com_o_diff(tmp_path):
    (tmp_path / "a.ts").write_text("const x = 1\nawait db.query(`SELECT * FROM u WHERE n = '${nome}'`)\n")
    t = TrechoArquivo("a.ts", [LinhaAdicionada(2, "await db.query(`SELECT * FROM u WHERE n = '${nome}'`)")])

    assert anexar_fontes([t], tmp_path) == 0
    assert t.fonte is not None


def test_js_join_e_sendfile_do_mesmo_fluxo_sao_reportados_uma_vez_so():
    codigo = "app.get('/d', (req, res) => {\n const n = req.query.a;\n const c = path.join(DIR, n);\n res.sendFile(c);\n});"

    resultado = analisar_ast_js("a.js", codigo)

    assert [(a.regra, a.linha) for a in resultado.achados] == [("ast-path-traversal", 4)]


def test_js_join_sozinho_ainda_e_reportado():
    resultado = analisar_ast_js("a.js", "app.get('/d', (req, res) => {\n const c = path.join(DIR, req.query.a);\n log(c);\n});")

    assert [a.regra for a in resultado.achados] == ["ast-path-traversal"]
