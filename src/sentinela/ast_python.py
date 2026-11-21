"""Análise de arquivos Python pela árvore sintática (módulo `ast`).

As regras por linha só enxergam o texto de uma linha. Aqui o arquivo é lido inteiro, e dá para:
- ligar a ORIGEM de um dado (request.args, parâmetro de rota) ao seu USO (open, requests.get),
  mesmo em linhas diferentes (análise de "taint", simplificada);
- ver strings montadas em várias linhas (SQL);
- olhar a rota inteira (decoradores, parâmetros, corpo) para achar falta de autenticação.

Só são "externos" os dados de uma aplicação web: `request` (quando o arquivo é de um framework web) e os
parâmetros de rotas. `input()` e sys.argv não contam: num script de terminal quem digita é o próprio usuário.

Limites (de propósito, para ficar explicável): a análise é por função, e ignora a ordem das linhas.
Só roda em Python.

Uma exceção: uma função solta no nível do módulo (não método, não aninhada) chamada DIRETO (`ajuda(x)`,
não `obj.ajuda(x)`) de outro lugar no MESMO arquivo propaga o dado contaminado para dentro dela — ver
`_resumo_por_parametro` e `_chamadas_para_funcoes_ajudantes`. Isso resolve a rota "fina" que só repassa
o parâmetro para quem faz o trabalho de verdade. Ainda não segue chamada para outro arquivo (precisaria
resolver import) nem uma função ajudante chamando outra ajudante (só um nível).
"""

import ast
import re
import warnings
from dataclasses import dataclass

from sentinela.models import Finding, Severity

# Chamadas que "limpam" um valor: o resultado deixa de ser perigoso para caminho, URL ou SQL.
SANITIZADORES = {
    "secure_filename", "basename", "int", "float", "bool", "len", "abs",
    "escape", "quote", "quote_plus", "slugify", "uuid4", "UUID",
}
CONSTANTE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SQL = re.compile(r"(?is)\b(select\b.+?\bfrom|insert\s+into|update\b.+?\bset|delete\s+from)\b")
AUTENTICACAO = re.compile(
    r"(?i)(current_user|usuario_atual|usuario_logado|logado|get_jwt|jwt|verify_|verificar_|authenticat|autentic"
    r"|authoriz|autoriz|permission|permiss|is_admin|require_|exige_|login_required|\bg\.user\b|request\.user\b|\b40[13]\b)"
)
# Depends(...)/Security(...) injeta algo na rota; só conta como autenticação se o nome sugerir isso
# (Depends(get_db) injeta o banco e não autentica ninguém).
DEPENDENCIA_AUTH = re.compile(r"(?i)(user|usuario|auth|autent|token|login|logado|atual|current|permiss|jwt|principal|admin|role|papel)")
WEB_FRAMEWORKS = {
    "flask", "django", "fastapi", "starlette", "bottle", "aiohttp", "sanic", "tornado",
    "falcon", "pyramid", "quart", "werkzeug",
}
METODOS_ROTA = {"get", "post", "put", "delete", "patch", "head", "options", "route", "api_route"}
METODOS_QUE_ALTERAM = {"put", "delete", "patch"}
SINKS_SQL = {"execute", "executemany", "executescript", "query", "raw", "text", "read_sql", "read_sql_query", "exec_driver_sql"}
SINKS_CAMINHO = {"open", "send_file", "FileResponse", "Path", "PurePath"}
SINKS_CAMINHO_PONTILHADOS = {
    "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.copytree", "shutil.move",
    "os.remove", "os.unlink", "os.rmdir", "os.listdir", "os.makedirs", "os.mkdir", "os.rename",
}
VERBOS_HTTP = {"get", "post", "put", "delete", "head", "patch", "options"}
SINKS_DESSERIALIZACAO = {
    "pickle.load", "pickle.loads", "pd.read_pickle", "pandas.read_pickle", "read_pickle",
    "joblib.load", "torch.load", "marshal.loads",
}

# id da regra -> (categoria, CWE, severidade, explicação, correção)
REGRAS_AST = {
    "ast-path-traversal": (
        "path traversal", "CWE-22", Severity.alta,
        "Um dado vindo da requisição chega a uma operação com arquivo sem ser limpo, e '../' pode escapar da pasta permitida.",
        "Limpe com secure_filename/os.path.basename ou confira com os.path.realpath que o caminho fica dentro da pasta base.",
    ),
    "ast-ssrf": (
        "SSRF", "CWE-918", Severity.alta,
        "Um dado vindo da requisição vira a URL de uma chamada do servidor, que pode ser apontada para serviços internos.",
        "Valide o host contra uma lista de permitidos e bloqueie endereços internos e de metadados.",
    ),
    "ast-desserializacao": (
        "desserialização insegura", "CWE-502", Severity.critica,
        "Um dado vindo da requisição é desserializado com um formato que pode executar código.",
        "Use um formato de dados puro (JSON) e nunca desserialize entrada de fora com pickle ou similares.",
    ),
    "ast-sql-concatenacao": (
        "SQL injection", "CWE-89", Severity.alta,
        "A consulta SQL é montada juntando texto com valores variáveis (mesmo em várias linhas), então uma entrada maliciosa muda a consulta.",
        "Use consulta parametrizada: execute('... WHERE nome = ?', (nome,)).",
    ),
    "ast-injecao-de-comando": (
        "injeção de comando", "CWE-78", Severity.critica,
        "Um dado vindo da requisição entra num comando executado por um shell.",
        "Use execFile/spawn com os argumentos em lista (sem shell) e valide a entrada.",
    ),
    "ast-xss-resposta": (
        "XSS", "CWE-79", Severity.media,
        "Um dado vindo da requisição é devolvido como HTML (ou inserido na página) sem escapar, abrindo espaço para script injetado.",
        "Escape o valor (ou use res.json / textContent) antes de colocá-lo no HTML.",
    ),
    "ast-filtro-postgrest": (
        "SQL injection", "CWE-89", Severity.media,
        "Um dado vindo da requisição entra num filtro em texto (.or/.filter do PostgREST/Supabase) e pode injetar condições extras.",
        "Use os métodos de filtro com valores separados (.eq, .ilike, .in) em vez de montar o texto do filtro.",
    ),
    "ast-falta-autorizacao-action": (
        "falta de autorização", "CWE-862", Severity.media,
        "Esta server action altera dados e pode ser chamada por qualquer visitante, mas não encontrei nela nenhuma verificação "
        "de login ou permissão. Se o controle é feito em outro lugar (RLS, middleware), ignore este aviso.",
        "Confira a sessão no começo da action e valide que o usuário pode mexer naquele recurso.",
    ),
    "ast-falta-autorizacao": (
        "falta de autorização", "CWE-862", Severity.media,
        "Esta rota altera dados (PUT/DELETE/PATCH), mas não encontrei nenhuma verificação de login ou permissão nela. "
        "Se a autenticação é feita em outro lugar (middleware, gateway), ignore este aviso.",
        "Exija autenticação (decorador ou dependência) e confira que o usuário pode mexer naquele recurso.",
    ),
}


def _ultimo_nome(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _nome_pontilhado(func: ast.expr) -> str | None:
    """`os.path.join` -> "os.path.join". None se não for uma cadeia simples de nomes."""
    partes = []
    while isinstance(func, ast.Attribute):
        partes.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        partes.append(func.id)
        return ".".join(reversed(partes))
    return None


def _raiz(node: ast.AST) -> ast.AST:
    while True:
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            return node


def _contaminado(n: ast.AST | None, taint: set[str], validados: set[str]) -> bool:
    """O valor da expressão depende de um dado externo (e não foi limpo nem validado)?"""
    if n is None or isinstance(n, (ast.Constant, ast.Compare, ast.Lambda)):
        return False
    if isinstance(n, ast.Name):
        return n.id in taint and n.id not in validados
    if isinstance(n, ast.Call):
        if _ultimo_nome(n.func) in SANITIZADORES:
            return False
        return (
            (isinstance(n.func, ast.Attribute) and _contaminado(n.func.value, taint, validados))
            or any(_contaminado(a, taint, validados) for a in n.args)
            or any(_contaminado(k.value, taint, validados) for k in n.keywords)
        )
    if isinstance(n, (ast.Attribute, ast.Subscript)):
        if isinstance(n, ast.Subscript) and _contaminado(n.slice, taint, validados):
            return True
        return _contaminado(n.value, taint, validados)
    return any(
        isinstance(c, ast.expr) and _contaminado(c, taint, validados) for c in ast.iter_child_nodes(n)
    )


def _nos_do_escopo(raiz: ast.AST):
    """Percorre o corpo de uma função (ou do módulo) sem entrar em funções, classes e lambdas aninhadas."""
    pilha = list(reversed(getattr(raiz, "body", [])))
    while pilha:
        no = pilha.pop()
        yield no
        if not isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pilha.extend(reversed(list(ast.iter_child_nodes(no))))


def _nomes_alvo(alvo: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(alvo) if isinstance(n, ast.Name)}


def _decoradores_de_rota(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    return [
        d for d in func.decorator_list
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in METODOS_ROTA
    ]


def _parametros_externos(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Em uma rota, os parâmetros vêm da URL/consulta, exceto os injetados por Depends/Security."""
    argumentos = func.args.posonlyargs + func.args.args + func.args.kwonlyargs
    defaults = [None] * (len(func.args.posonlyargs + func.args.args) - len(func.args.defaults)) + list(func.args.defaults)
    defaults += list(func.args.kw_defaults)
    externos = set()
    for arg, default in zip(argumentos, defaults):
        injetado = isinstance(default, ast.Call) and _ultimo_nome(default.func) in {"Depends", "Security"}
        if arg.arg not in {"self", "cls", "request"} and not injetado:
            externos.add(arg.arg)
    return externos


def _guardas_de_validacao(nos: list[ast.AST]) -> set[str]:
    """`if X not in PERMITIDOS: abort/raise/return` valida os nomes usados em X."""
    validados: set[str] = set()
    for no in nos:
        if not isinstance(no, ast.If) or not isinstance(no.test, ast.Compare):
            continue
        if not any(isinstance(op, ast.NotIn) for op in no.test.ops):
            continue
        sai = any(
            isinstance(s, (ast.Raise, ast.Return))
            or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and _ultimo_nome(s.value.func) in {"abort", "exit"})
            for s in no.body
        )
        if sai:
            validados |= _nomes_alvo(no.test.left)
    return validados


def _propagar(nos: list[ast.AST], taint: set[str], validados: set[str]) -> None:
    """Marca como contaminadas as variáveis que recebem um valor contaminado (ponto fixo, poucas voltas)."""
    for _ in range(4):
        antes = len(taint)
        for no in nos:
            if isinstance(no, ast.Assign) and _contaminado(no.value, taint, validados):
                for alvo in no.targets:
                    taint |= _nomes_alvo(alvo)
            elif isinstance(no, ast.AnnAssign) and no.value and _contaminado(no.value, taint, validados):
                taint |= _nomes_alvo(no.target)
            elif isinstance(no, ast.AugAssign) and _contaminado(no.value, taint, validados):
                taint |= _nomes_alvo(no.target)
            elif isinstance(no, (ast.For, ast.AsyncFor)) and _contaminado(no.iter, taint, validados):
                taint |= _nomes_alvo(no.target)
        if len(taint) == antes:
            return


def _argumentos(chamada: ast.Call) -> list[ast.expr]:
    return list(chamada.args) + [k.value for k in chamada.keywords]


def _sql_dinamico(expr: ast.AST, validados: set[str]) -> bool:
    """A expressão monta uma consulta SQL juntando texto fixo com valores variáveis?"""
    if isinstance(expr, ast.JoinedStr):
        texto = "".join(v.value for v in expr.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        dinamicos = [v.value for v in expr.values if isinstance(v, ast.FormattedValue)]
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        partes: list[ast.expr] = []

        def achatar(n: ast.expr) -> None:
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                achatar(n.left)
                achatar(n.right)
            else:
                partes.append(n)

        if isinstance(expr.op, ast.Mod):
            direita = expr.right
            partes = [expr.left]
            partes += list(direita.elts) if isinstance(direita, ast.Tuple) else [direita]
        else:
            achatar(expr)
        textos = [p.value for p in partes if isinstance(p, ast.Constant) and isinstance(p.value, str)]
        texto = " ".join(textos)
        dinamicos = [p for p in partes if not (isinstance(p, ast.Constant) and isinstance(p.value, str))]
    elif (
        isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format"
        and isinstance(expr.func.value, ast.Constant) and isinstance(expr.func.value.value, str)
    ):
        texto = expr.func.value.value
        dinamicos = _argumentos(expr)
    else:
        return False

    if not SQL.search(texto):
        return False

    def conta(d: ast.AST) -> bool:
        if isinstance(d, ast.Constant):
            return False
        if isinstance(d, ast.Name) and (CONSTANTE.match(d.id) or d.id in validados):
            return False
        if isinstance(d, ast.Call):
            nome = _ultimo_nome(d.func)
            if nome in SANITIZADORES:
                return False
            if nome in {"str", "repr"}:  # só converte para texto: vale o que está dentro (str(int(n)) é seguro)
                return any(conta(a) for a in d.args)
        return True

    return any(conta(d) for d in dinamicos)


def _achado(regra: str, arquivo: str, linha: int) -> Finding:
    categoria, cwe, severidade, explicacao, correcao = REGRAS_AST[regra]
    return Finding(
        arquivo=arquivo, linha=linha, severidade=severidade, categoria=categoria,
        cwe=cwe, regra=regra, explicacao=explicacao, correcao=correcao,
    )


def _contexto_web(arvore: ast.AST) -> bool:
    """O arquivo é de uma aplicação web? (importa um framework web ou declara rotas)"""
    for no in ast.walk(arvore):
        if isinstance(no, ast.Import) and any(a.name.split(".")[0] in WEB_FRAMEWORKS for a in no.names):
            return True
        if isinstance(no, ast.ImportFrom) and (no.module or "").split(".")[0] in WEB_FRAMEWORKS:
            return True
        if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)) and _decoradores_de_rota(no):
            return True
    return False


def _achados_por_sinks(arquivo: str, nos: list[ast.AST], taint: set[str], validados: set[str]) -> list[Finding]:
    """Sinks (SQL, caminho de arquivo, desserialização, SSRF) alcançados a partir de `taint`, já com
    `validados` descontado. Separado de `_analisar_escopo` para ser reaproveitado tanto no escopo normal
    (dado vindo da própria rota) quanto no resumo por parâmetro de uma função ajudante (ver
    `_resumo_por_parametro`): o cálculo de "o que esse dado alcança" é o mesmo nos dois casos."""
    achados: list[Finding] = []

    def contaminado(e: ast.AST | None) -> bool:
        return _contaminado(e, taint, validados)

    # --- SQL montado por concatenação/formatação, em qualquer número de linhas ---
    nomes_em_sinks = set()
    for no in nos:
        if isinstance(no, ast.Call) and _ultimo_nome(no.func) in SINKS_SQL and no.args:
            primeiro = no.args[0]
            if isinstance(primeiro, ast.Name):
                nomes_em_sinks.add(primeiro.id)
            elif _sql_dinamico(primeiro, validados):
                achados.append(_achado("ast-sql-concatenacao", arquivo, primeiro.lineno))
    for no in nos:
        if isinstance(no, ast.Assign) and any(isinstance(t, ast.Name) and t.id in nomes_em_sinks for t in no.targets):
            if _sql_dinamico(no.value, validados):
                achados.append(_achado("ast-sql-concatenacao", arquivo, no.value.lineno))

    # --- dados externos chegando a operações perigosas ---
    caminhos: list[tuple[Finding, bool]] = []  # (achado, fraco?)
    for no in nos:
        if not isinstance(no, ast.Call):
            continue
        nome = _nome_pontilhado(no.func)
        ultimo = _ultimo_nome(no.func)
        argumentos = _argumentos(no)
        if nome is None:
            continue

        if (
            nome in SINKS_CAMINHO or nome in SINKS_CAMINHO_PONTILHADOS or nome.endswith("path.join")
        ) and any(contaminado(a) for a in argumentos):
            caminhos.append((_achado("ast-path-traversal", arquivo, no.lineno), nome.endswith("path.join")))
        elif nome in SINKS_DESSERIALIZACAO and any(contaminado(a) for a in argumentos):
            achados.append(_achado("ast-desserializacao", arquivo, no.lineno))
        elif (
            (nome.split(".")[0] in {"requests", "httpx"} and ultimo in VERBOS_HTTP | {"request"})
            or nome in {"urlopen", "urllib.request.urlopen"}
        ):
            posicao = 1 if ultimo == "request" else 0
            url = next((k.value for k in no.keywords if k.arg == "url"), None)
            if url is None and len(no.args) > posicao:
                url = no.args[posicao]
            if contaminado(url):
                achados.append(_achado("ast-ssrf", arquivo, no.lineno))

    # O os.path.join com dado externo é um sinal fraco: se o resultado chega a uma operação de arquivo de verdade
    # (open, send_file...), só essa é reportada, para o mesmo fluxo não aparecer duas vezes.
    fortes = [f for f, fraco in caminhos if not fraco]
    achados += fortes or [f for f, _ in caminhos]
    return achados


def _analisar_escopo(
    arquivo: str,
    escopo: ast.AST,
    web: bool,
    funcoes_topo: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    resumos: dict[str, dict[str, list[Finding]]],
) -> list[Finding]:
    nos = list(_nos_do_escopo(escopo))
    # `request` só é um dado de usuário em arquivos de aplicação web; em bibliotecas HTTP é outra coisa.
    taint: set[str] = {"request"} if web else set()
    rota = isinstance(escopo, (ast.FunctionDef, ast.AsyncFunctionDef)) and bool(_decoradores_de_rota(escopo))
    if rota:
        taint |= _parametros_externos(escopo)
    validados = _guardas_de_validacao(nos)
    _propagar(nos, taint, validados)

    achados = _achados_por_sinks(arquivo, nos, taint, validados)
    achados += _chamadas_para_funcoes_ajudantes(nos, taint, validados, funcoes_topo, resumos)

    # --- rota que altera dados sem autenticação visível ---
    if rota:
        achados += _checar_autorizacao(arquivo, escopo)
    return achados


def _funcoes_de_nivel_superior(arvore: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Funções soltas no nível do módulo (não métodos, não aninhadas): candidatas a serem chamadas
    como 'função ajudante' de outro lugar no mesmo arquivo."""
    return {no.name: no for no in arvore.body if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _parametros_simples(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Nomes dos parâmetros (posicionais e nomeados), na ordem, sem self/cls."""
    args = func.args.posonlyargs + func.args.args + func.args.kwonlyargs
    return [a.arg for a in args if a.arg not in {"self", "cls"}]


def _resumo_por_parametro(arquivo: str, func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, list[Finding]]:
    """Para uma função de nível superior: se SÓ este parâmetro viesse contaminado (os outros não),
    quais achados o corpo dela produziria? Roda uma vez por parâmetro para saber exatamente qual é
    o perigoso — não é o mesmo que rodar com todos contaminados de uma vez, que não diria qual."""
    nos = list(_nos_do_escopo(func))
    validados = _guardas_de_validacao(nos)
    resumo: dict[str, list[Finding]] = {}
    for nome in _parametros_simples(func):
        taint = {nome}
        _propagar(nos, taint, validados)
        resumo[nome] = _achados_por_sinks(arquivo, nos, taint, validados)
    return resumo


def _args_por_parametro(chamada: ast.Call, func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.expr]:
    """Liga cada argumento de uma chamada ao nome do parâmetro correspondente da função chamada
    (por posição ou por nome)."""
    parametros = _parametros_simples(func)
    ligados: dict[str, ast.expr] = {}
    for i, arg in enumerate(chamada.args):
        if i < len(parametros):
            ligados[parametros[i]] = arg
    for kw in chamada.keywords:
        if kw.arg in parametros:
            ligados[kw.arg] = kw.value
    return ligados


def _chamadas_para_funcoes_ajudantes(
    nos: list[ast.AST],
    taint: set[str],
    validados: set[str],
    funcoes_topo: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    resumos: dict[str, dict[str, list[Finding]]],
) -> list[Finding]:
    """Chamada direta (`ajuda(x)`, não `obj.ajuda(x)`) para uma função do mesmo arquivo: se o argumento
    passado está contaminado aqui, traz os achados que o resumo dessa função já calculou para o
    parâmetro correspondente. Só um nível (a função ajudante chamando outra ajudante não é seguido)."""
    achados: list[Finding] = []
    for no in nos:
        if not (isinstance(no, ast.Call) and isinstance(no.func, ast.Name)):
            continue
        func = funcoes_topo.get(no.func.id)
        if func is None:
            continue
        for parametro, arg in _args_por_parametro(no, func).items():
            if _contaminado(arg, taint, validados):
                achados += resumos[no.func.id].get(parametro, [])
    return achados


def _checar_autorizacao(arquivo: str, func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Finding]:
    altera = False
    for d in _decoradores_de_rota(func):
        if d.func.attr in METODOS_QUE_ALTERAM:
            altera = True
        for k in d.keywords:
            if k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple, ast.Set)):
                altera |= any(
                    isinstance(e, ast.Constant) and str(e.value).lower() in METODOS_QUE_ALTERAM for e in k.value.elts
                )
    if not altera:
        return []

    defaults = list(func.args.defaults) + [d for d in func.args.kw_defaults if d is not None]
    if any(
        isinstance(d, ast.Call) and _ultimo_nome(d.func) in {"Depends", "Security"} and DEPENDENCIA_AUTH.search(ast.unparse(d))
        for d in defaults
    ):
        return []

    # Procura sinal de autenticação fora do decorador da rota (que tem o caminho, ex.: "/permissions").
    rotas = set(_decoradores_de_rota(func))
    texto = "\n".join(
        [ast.unparse(d) for d in func.decorator_list if d not in rotas]
        + [ast.unparse(func.args)]
        + [ast.unparse(s) for s in func.body]
    )
    if AUTENTICACAO.search(texto):
        return []
    return [_achado("ast-falta-autorizacao", arquivo, func.lineno)]


@dataclass
class ResultadoAst:
    achados: list[Finding]
    # Linhas que são só texto solto (docstrings, strings sem uso): código mencionado ali não executa,
    # então as regras por linha ignoram achados nessas linhas.
    linhas_de_texto: set[int]


def _linhas_de_texto(arvore: ast.AST) -> set[int]:
    linhas: set[int] = set()
    for no in ast.walk(arvore):
        if isinstance(no, ast.Expr) and isinstance(no.value, ast.Constant) and isinstance(no.value.value, str):
            linhas |= set(range(no.lineno, (no.end_lineno or no.lineno) + 1))
    return linhas


def analisar_ast(arquivo: str, fonte: str) -> ResultadoAst | None:
    """Resultado da análise por AST, ou None se o arquivo não puder ser analisado (erro de sintaxe etc.)."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # avisos de sintaxe (ex.: escape inválido) não são nossos
            arvore = ast.parse(fonte)
        escopos = [arvore] + [n for n in ast.walk(arvore) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        web = _contexto_web(arvore)
        funcoes_topo = _funcoes_de_nivel_superior(arvore)
        resumos = {nome: _resumo_por_parametro(arquivo, f) for nome, f in funcoes_topo.items()}
        achados: list[Finding] = []
        for escopo in escopos:
            achados += _analisar_escopo(arquivo, escopo, web, funcoes_topo, resumos)
        return ResultadoAst(achados, _linhas_de_texto(arvore))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
