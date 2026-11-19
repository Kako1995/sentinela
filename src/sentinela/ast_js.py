"""Análise de JavaScript/TypeScript pela árvore sintática (tree-sitter).

Mesma ideia da análise de Python: ler o arquivo inteiro e ligar a ORIGEM de um dado (`req.query`,
`request.json()`, argumentos de server actions do Next.js) ao seu USO (`fs.readFile`, `fetch`, `query`),
mesmo em linhas diferentes, além de olhar a rota/função inteira para achar falta de autenticação.

Cobre Express e similares, route handlers e server actions do Next.js e o filtro `.or()` do Supabase.
Limites: por função (sem seguir chamadas entre funções nem arquivos) e sem tipos: um valor
validado por `zod` continua contando como externo.
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from sentinela.ast_python import CONSTANTE, SQL, ResultadoAst, _achado

try:
    import tree_sitter_javascript as _tsjs
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Node, Parser

    _DISPONIVEL = True
except ImportError:  # sem tree-sitter instalado, só a análise por linha e a de Python funcionam
    _DISPONIVEL = False

EXTENSOES_JS = {".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "ts", ".mts": "ts", ".cts": "ts", ".tsx": "tsx"}

FUNCOES = {
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function_declaration", "generator_function",
}
LITERAIS = {"string", "number", "true", "false", "null", "undefined", "regex", "type_annotation", "type_arguments"}
SANITIZADORES = {
    "Number", "parseInt", "parseFloat", "Boolean", "encodeURIComponent", "encodeURI", "basename",
    "escape", "escapeHtml", "sanitize", "sanitizeHtml", "isNaN", "isFinite",
}
MODULOS_WEB = {
    "express", "fastify", "koa", "hono", "restify", "micro", "h3", "@hapi/hapi", "@sveltejs/kit",
    "@remix-run/node", "next-auth",
}
METODOS_HTTP_NEXT = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
FS = {
    "readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
    "createReadStream", "createWriteStream", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
    "readdir", "readdirSync", "stat", "statSync", "lstat", "access", "mkdir", "mkdirSync", "rename",
    "copyFile", "open", "openSync",
}
OBJETOS_FS = {"fs", "fsp", "promises"}
SINKS_SQL = {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "queryRawUnsafe", "executeRawUnsafe", "unsafe"}
OBJETOS_HTTP = {"axios", "got", "ky", "needle", "superagent", "http", "https"}
VERBOS_HTTP = {"get", "post", "put", "delete", "head", "patch", "request", "options"}
OBJETOS_RESPOSTA = {"res", "response", "reply"}
OBJETOS_ROTEADOR = {"app", "router", "server", "api", "routes"}
TAG_HTML = re.compile(r"<(?:a|b|i|p|br|div|span|h[1-6]|ul|ol|li|table|tr|td|th|img|input|form|script|style|button|label|strong|em|pre|code|iframe|body|html|head|title)\b")
HOST_FIXO = re.compile(r"^https?://[^/?#${}\s]+[/?#]")
AUTENTICACAO = re.compile(
    # requireMaster(), assertAdmin(), ensureLoggedIn(): helpers que exigem login/permissão (maiúscula depois do prefixo,
    # para não casar `required` nem `requestInvoice`)
    r"(?-i:\b(?:require|assert|ensure)[A-Z]\w*)|(?i:\bauth\b|\bauth\(|authenticat|authoriz|isauth|requireauth|withauth|getauth|session|getuser|currentuser"
    r"|requireuser|passport|jwt|verifytoken|\btoken\b|login|permission|\broles?\b|guard|protect|createclient"
    r"|createserverclient|supabase\.auth|req\.user|request\.user|status\(\s*40[13]\s*\)|\b40[13]\b)"
)
# Nomes de server actions que alteram dados (en e pt). As que só leem costumam ser públicas de propósito.
ACAO_QUE_ALTERA = re.compile(
    r"(?i)^(delete|remove|destroy|update|edit|save|create|insert|cancel|archive|invite|assign|set|change|add"
    r"|apagar|excluir|remover|atualizar|editar|salvar|criar|cancelar|arquivar|convidar|alterar|adicionar)"
)
SAI = {"return_statement", "throw_statement", "continue_statement", "break_statement"}
FUNCOES_DE_SAIDA = {"notFound", "redirect", "abort"}


@dataclass
class _Ctx:
    taint: set[str]
    validados: set[str] = field(default_factory=set)


# ---------- utilidades sobre nós ----------


def _t(n: "Node | None") -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _linha(n: "Node") -> int:
    return n.start_point[0] + 1


def _ultimo_nome(fn: "Node | None") -> str | None:
    if fn is None:
        return None
    if fn.type == "identifier":
        return _t(fn)
    if fn.type == "member_expression":
        return _t(fn.child_by_field_name("property"))
    return None


def _nome_pontilhado(fn: "Node | None") -> str | None:
    """`fs.promises.readFile` -> "fs.promises.readFile"; None se não for uma cadeia simples de nomes."""
    if fn is None:
        return None
    if fn.type == "identifier":
        return _t(fn)
    if fn.type == "member_expression":
        base = _nome_pontilhado(fn.child_by_field_name("object"))
        return f"{base}.{_t(fn.child_by_field_name('property'))}" if base else None
    return None


def _descendentes(n: "Node", parar_em_funcoes: bool = True):
    pilha = list(reversed(n.children))
    while pilha:
        no = pilha.pop()
        yield no
        if not (parar_em_funcoes and no.type in FUNCOES):
            pilha.extend(reversed(no.children))


def _identificadores(n: "Node") -> set[str]:
    """Nomes ligados por um padrão (`x`, `{ a, b: c }`, `[d, e]`), ignorando anotações de tipo."""
    nomes = set()
    pilha = [n]
    while pilha:
        no = pilha.pop()
        if no.type in {"type_annotation", "type_arguments"}:
            continue
        if no.type in {"identifier", "shorthand_property_identifier_pattern"}:
            nomes.add(_t(no))
        pilha.extend(no.children)
    return nomes


def _nomes_dos_parametros(func: "Node") -> set[str]:
    params = func.child_by_field_name("parameters")
    if params is None:  # arrow function com um parâmetro sem parênteses: x => ...
        unico = func.child_by_field_name("parameter")
        return _identificadores(unico) if unico is not None else set()
    return _identificadores(params)


# ---------- dado externo (taint) ----------


def _contaminado(n: "Node | None", ctx: _Ctx) -> bool:
    if n is None or n.type in LITERAIS or n.type in FUNCOES:
        return False
    if n.type == "identifier":
        return _t(n) in ctx.taint and _t(n) not in ctx.validados
    if n.type == "call_expression":
        fn = n.child_by_field_name("function")
        if _ultimo_nome(fn) in SANITIZADORES:
            return False
        args = n.child_by_field_name("arguments")
        if fn is not None and fn.type == "member_expression" and _contaminado(fn.child_by_field_name("object"), ctx):
            return True
        return args is not None and any(_contaminado(a, ctx) for a in args.named_children)
    if n.type == "member_expression":
        return _contaminado(n.child_by_field_name("object"), ctx)
    if n.type == "subscript_expression":
        return _contaminado(n.child_by_field_name("object"), ctx) or _contaminado(n.child_by_field_name("index"), ctx)
    if n.type == "template_string":
        return any(
            _contaminado(c, ctx) for s in n.named_children if s.type == "template_substitution" for c in s.named_children
        )
    return any(_contaminado(c, ctx) for c in n.named_children)


def _propagar(nos: list["Node"], ctx: _Ctx) -> None:
    for _ in range(4):
        antes = len(ctx.taint)
        for no in nos:
            if no.type == "variable_declarator":
                if _contaminado(no.child_by_field_name("value"), ctx):
                    ctx.taint |= _identificadores(no.child_by_field_name("name"))
            elif no.type in {"assignment_expression", "augmented_assignment_expression"}:
                esquerda = no.child_by_field_name("left")
                if esquerda is not None and esquerda.type in {"identifier", "object_pattern", "array_pattern"}:
                    if _contaminado(no.child_by_field_name("right"), ctx):
                        ctx.taint |= _identificadores(esquerda)
        if len(ctx.taint) == antes:
            return


def _guardas_de_validacao(nos: list["Node"]) -> set[str]:
    """`if (!LISTA.includes(x)) return ...` ou `if (!/regex/.test(x)) throw ...` valida o x."""
    validados: set[str] = set()
    for no in nos:
        if no.type != "if_statement":
            continue
        consequencia = no.child_by_field_name("consequence")
        if consequencia is None or not any(
            d.type in SAI or (d.type == "call_expression" and _ultimo_nome(d.child_by_field_name("function")) in FUNCOES_DE_SAIDA)
            for d in [consequencia, *_descendentes(consequencia)]
        ):
            continue
        for d in _descendentes(no.child_by_field_name("condition")):
            if d.type != "unary_expression" or _t(d.child_by_field_name("operator")) != "!":
                continue
            alvo = d.child_by_field_name("argument")
            while alvo is not None and alvo.type == "parenthesized_expression" and alvo.named_children:
                alvo = alvo.named_children[0]
            if alvo is None or alvo.type != "call_expression":
                continue
            fn = alvo.child_by_field_name("function")
            metodo = _ultimo_nome(fn)
            if metodo in {"includes", "has", "test"}:
                validados |= _identificadores(alvo.child_by_field_name("arguments"))
            elif metodo == "match" and fn is not None and fn.type == "member_expression":
                validados |= _identificadores(fn.child_by_field_name("object"))
    return validados


# ---------- strings e SQL ----------


def _conteudo_string(n: "Node") -> str:
    return _t(n)[1:-1] if n.type == "string" else ""


def _partes_de_texto(n: "Node") -> tuple[str, list["Node"]]:
    """(texto fixo junto, expressões dinâmicas) de um template literal ou de uma cadeia de `+`."""
    if n.type == "template_string":
        texto = " ".join(_t(c) for c in n.named_children if c.type in {"string_fragment", "escape_sequence"})
        dinamicos = [c for s in n.named_children if s.type == "template_substitution" for c in s.named_children]
        return texto, dinamicos
    if n.type == "binary_expression" and _t(n.child_by_field_name("operator")) == "+":
        t1, d1 = _partes_de_texto(n.child_by_field_name("left"))
        t2, d2 = _partes_de_texto(n.child_by_field_name("right"))
        return f"{t1} {t2}", d1 + d2
    if n.type == "string":
        return _conteudo_string(n), []
    if n.type in {"parenthesized_expression", "await_expression", "as_expression", "satisfies_expression"} and n.named_children:
        return _partes_de_texto(n.named_children[0])
    return "", [n]


def _conta_como_dinamico(d: "Node", ctx: _Ctx) -> bool:
    if d.type in LITERAIS:
        return False
    if d.type == "identifier" and (CONSTANTE.match(_t(d)) or _t(d) in ctx.validados):
        return False
    return not (d.type == "call_expression" and _ultimo_nome(d.child_by_field_name("function")) in SANITIZADORES)


def _sql_dinamico(expr: "Node", ctx: _Ctx) -> bool:
    texto, dinamicos = _partes_de_texto(expr)
    return bool(SQL.search(texto)) and any(_conta_como_dinamico(d, ctx) for d in dinamicos)


def _prefixo_literal(n: "Node") -> str:
    """Texto fixo que COMEÇA a string (até a primeira parte dinâmica)."""
    if n.type == "string":
        return _conteudo_string(n)
    if n.type == "template_string":
        prefixo = ""
        for c in n.named_children:
            if c.type == "template_substitution":
                break
            prefixo += _t(c) if c.type in {"string_fragment", "escape_sequence"} else ""
        return prefixo
    if n.type == "binary_expression" and _t(n.child_by_field_name("operator")) == "+":
        return _prefixo_literal(n.child_by_field_name("left"))
    return ""


# ---------- análise de uma função / do módulo ----------


@dataclass
class _Arquivo:
    nome: str
    web: bool
    acao_de_servidor: bool  # arquivo 'use server'
    stem: str
    fs_importados: set[str]  # nomes de funções do fs importadas diretamente (import { readFile } from 'fs')
    protegido_por_use: bool  # algum router.use(...) de autenticação


def _tem_diretiva(corpo: "Node | None", texto: str) -> bool:
    if corpo is None:
        return False
    for filho in corpo.named_children:
        if filho.type == "expression_statement" and filho.named_children and filho.named_children[0].type == "string":
            if _conteudo_string(filho.named_children[0]) == texto:
                return True
        elif filho.type != "comment":
            break
    return False


def _importado(raiz: "Node") -> tuple[set[str], bool]:
    """(nomes importados de 'fs', arquivo importa um módulo web?)"""
    fs_nomes: set[str] = set()
    web = False
    for no in _descendentes(raiz, parar_em_funcoes=False):
        modulo = None
        if no.type == "import_statement":
            origem = no.child_by_field_name("source")
            modulo = _conteudo_string(origem) if origem is not None else None
            if modulo in {"fs", "node:fs", "fs/promises", "node:fs/promises"}:
                for filho in _descendentes(no, parar_em_funcoes=False):
                    if filho.type == "import_specifier":
                        nome = filho.child_by_field_name("name")
                        fs_nomes.add(_t(nome))
        elif no.type == "call_expression" and _t(no.child_by_field_name("function")) == "require":
            args = no.child_by_field_name("arguments")
            if args is not None and args.named_children and args.named_children[0].type == "string":
                modulo = _conteudo_string(args.named_children[0])
        if modulo and (modulo in MODULOS_WEB or modulo == "next" or modulo.startswith("next/")):
            web = True
    return fs_nomes, web


def _chamadas_de_rota(raiz: "Node") -> bool:
    for no in _descendentes(raiz, parar_em_funcoes=False):
        if no.type == "call_expression":
            fn = no.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression" and _t(fn.child_by_field_name("object")) in OBJETOS_ROTEADOR:
                if _ultimo_nome(fn) in {"get", "post", "put", "delete", "patch", "use"}:
                    return True
    return False


def _arquivo(arquivo: str, raiz: "Node") -> _Arquivo:
    fs_nomes, importa_web = _importado(raiz)
    stem = PurePosixPath(arquivo).stem
    acao = _tem_diretiva(raiz, "use server")
    protegido = False
    for no in _descendentes(raiz, parar_em_funcoes=False):
        if no.type == "call_expression":
            fn = no.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression" and _ultimo_nome(fn) == "use":
                protegido |= bool(AUTENTICACAO.search(_t(no.child_by_field_name("arguments"))))
    web = importa_web or acao or stem in {"route", "page", "layout", "middleware"} or _chamadas_de_rota(raiz)
    return _Arquivo(arquivo, web, acao, stem, fs_nomes, protegido)


def _funcao_exportada(func: "Node") -> tuple[str | None, bool]:
    """(nome, exportada?) de uma função declarada, ou de uma arrow function atribuída a uma const."""
    if func.type == "function_declaration":
        nome = _t(func.child_by_field_name("name"))
        return nome, func.parent is not None and func.parent.type == "export_statement"
    pai = func.parent
    if pai is not None and pai.type == "variable_declarator":
        nome = _t(pai.child_by_field_name("name"))
        decl = pai.parent.parent if pai.parent is not None else None
        return nome, decl is not None and decl.type == "export_statement"
    return None, False


def _eh_fs(nome: str | None, ultimo: str | None, arq: _Arquivo) -> bool:
    if ultimo not in FS or nome is None:
        return False
    if nome.split(".")[0] in OBJETOS_FS:
        return True
    # Nome solto: vale se foi importado do fs. Os terminados em Sync e os streams são do fs mesmo sem o import visível.
    return nome == ultimo and (ultimo in arq.fs_importados or ultimo.endswith("Sync") or ultimo.startswith("createRead") or ultimo.startswith("createWrite"))


def _arg_url(chamada: "Node") -> "Node | None":
    args = chamada.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return None
    primeiro = args.named_children[0]
    if primeiro.type == "object":  # axios({ url: ... })
        for par in primeiro.named_children:
            if par.type == "pair" and _t(par.child_by_field_name("key")) == "url":
                return par.child_by_field_name("value")
        return None
    return primeiro


def _analisar_funcao_ou_modulo(escopo: "Node", pai_taint: set[str], arq: _Arquivo, achados: list, raiz_modulo: bool) -> None:
    nos: list["Node"] = []
    aninhadas: list["Node"] = []
    corpo = escopo if raiz_modulo else escopo.child_by_field_name("body")
    pilha = list(reversed(corpo.children)) if corpo is not None else []
    while pilha:
        no = pilha.pop()
        if no.type in FUNCOES:
            aninhadas.append(no)
            continue
        nos.append(no)
        pilha.extend(reversed(no.children))

    ctx = _Ctx(taint=set(pai_taint))
    if arq.web:
        ctx.taint |= {"req", "request"}
    if not raiz_modulo:
        nome, exportada = _funcao_exportada(escopo)
        corpo_dir = escopo.child_by_field_name("body")
        e_acao = (arq.acao_de_servidor and exportada) or _tem_diretiva(corpo_dir, "use server")
        e_handler_next = arq.stem == "route" and exportada and nome in METODOS_HTTP_NEXT
        e_pagina = arq.stem in {"page", "layout"} and exportada
        if e_acao or e_handler_next or e_pagina:
            ctx.taint |= _nomes_dos_parametros(escopo)  # vêm do navegador / da URL
        _checar_autorizacao_da_funcao(escopo, nome, e_acao, e_handler_next, arq, achados)
    ctx.validados = _guardas_de_validacao(nos)
    _propagar(nos, ctx)

    definicoes = {
        _t(n.child_by_field_name("name")): n.child_by_field_name("value")
        for n in nos if n.type == "variable_declarator" and n.child_by_field_name("name") is not None
        and n.child_by_field_name("name").type == "identifier" and n.child_by_field_name("value") is not None
    }
    _checar_sinks(nos, ctx, definicoes, arq, achados)
    if raiz_modulo:
        _checar_rotas_express(nos, arq, achados)

    for f in aninhadas:
        _analisar_funcao_ou_modulo(f, ctx.taint, arq, achados, raiz_modulo=False)


def _checar_sinks(nos: list["Node"], ctx: _Ctx, definicoes: dict, arq: _Arquivo, achados: list) -> None:
    caminhos: list[tuple] = []  # (achado, fraco?): path.join com dado externo é um sinal fraco
    for no in nos:
        if no.type == "assignment_expression":
            esq = no.child_by_field_name("left")
            if esq is not None and esq.type == "member_expression" and _t(esq.child_by_field_name("property")) in {"innerHTML", "outerHTML"}:
                if _contaminado(no.child_by_field_name("right"), ctx):
                    achados.append(_achado("ast-xss-resposta", arq.nome, _linha(no)))
            continue
        if no.type != "call_expression":
            continue
        fn = no.child_by_field_name("function")
        args = no.child_by_field_name("arguments")
        if fn is None or args is None or args.type != "arguments":  # template com tag (sql`...`): é parametrizado
            continue
        argumentos = list(args.named_children)
        nome = _nome_pontilhado(fn)
        ultimo = _ultimo_nome(fn)
        objeto = _t(fn.child_by_field_name("object")) if fn.type == "member_expression" else None

        # caminho de arquivo
        if (
            _eh_fs(nome, ultimo, arq)
            or (ultimo in {"sendFile", "download"} and objeto in OBJETOS_RESPOSTA)
            or nome in {"path.join", "path.resolve", "path.normalize"}
        ) and any(_contaminado(a, ctx) for a in argumentos):
            caminhos.append((_achado("ast-path-traversal", arq.nome, _linha(no)), nome in {"path.join", "path.resolve", "path.normalize"}))

        # SSRF
        elif nome in {"fetch", "axios", "got", "needle", "request"} or (objeto in OBJETOS_HTTP and ultimo in VERBOS_HTTP):
            url = _arg_url(no)
            if url is not None and _contaminado(url, ctx) and not HOST_FIXO.match(_prefixo_literal(url)):
                achados.append(_achado("ast-ssrf", arq.nome, _linha(no)))

        # SQL montado como texto
        elif ultimo in SINKS_SQL and argumentos:
            expr = argumentos[0]
            if expr.type == "identifier" and _t(expr) in definicoes:
                expr = definicoes[_t(expr)]
            if _sql_dinamico(expr, ctx):
                achados.append(_achado("ast-sql-concatenacao", arq.nome, _linha(expr)))

        # filtro em texto do PostgREST/Supabase
        elif ultimo in {"or", "filter"} and argumentos and argumentos[0].type in {"template_string", "binary_expression"}:
            if _contaminado(argumentos[0], ctx):
                achados.append(_achado("ast-filtro-postgrest", arq.nome, _linha(no)))

        # comando de shell
        elif ultimo in {"exec", "execSync"} and (objeto is None or objeto in {"child_process", "cp", "childProcess"}):
            if argumentos and _contaminado(argumentos[0], ctx):
                achados.append(_achado("ast-injecao-de-comando", arq.nome, _linha(no)))

        # HTML na resposta
        elif ultimo in {"send", "write", "end"} and objeto in OBJETOS_RESPOSTA and argumentos:
            alvo = argumentos[0]
            texto, _ = _partes_de_texto(alvo)
            if _contaminado(alvo, ctx) and (TAG_HTML.search(texto) or alvo.type in {"identifier", "member_expression", "subscript_expression"}):
                achados.append(_achado("ast-xss-resposta", arq.nome, _linha(no)))

    fortes = [f for f, fraco in caminhos if not fraco]
    achados += fortes or [f for f, _ in caminhos]


def _checar_autorizacao_da_funcao(func: "Node", nome: str | None, e_acao: bool, e_handler: bool, arq: _Arquivo, achados: list) -> None:
    texto = _t(func)
    if AUTENTICACAO.search(texto):
        return
    if e_handler and nome in {"PUT", "PATCH", "DELETE"}:
        achados.append(_achado("ast-falta-autorizacao", arq.nome, _linha(func)))
    elif e_acao and nome and ACAO_QUE_ALTERA.match(nome):
        achados.append(_achado("ast-falta-autorizacao-action", arq.nome, _linha(func)))


def _checar_rotas_express(nos: list["Node"], arq: _Arquivo, achados: list) -> None:
    """app.delete('/x', handler): handler visível, sem middleware nem sinal de autenticação."""
    if arq.protegido_por_use:
        return
    for no in nos:
        if no.type != "call_expression":
            continue
        fn = no.child_by_field_name("function")
        args = no.child_by_field_name("arguments")
        if fn is None or args is None or fn.type != "member_expression":
            continue
        if _t(fn.child_by_field_name("object")) not in OBJETOS_ROTEADOR or _ultimo_nome(fn) not in {"put", "delete", "patch"}:
            continue
        argumentos = list(args.named_children)
        if len(argumentos) < 2 or argumentos[0].type not in {"string", "template_string"}:
            continue
        *meio, ultimo = argumentos[1:]
        if ultimo.type not in FUNCOES:
            continue  # handler em outro arquivo/variável: não dá para ver
        if any(AUTENTICACAO.search(_t(m)) for m in meio) or AUTENTICACAO.search(_t(ultimo)):
            continue
        achados.append(_achado("ast-falta-autorizacao", arq.nome, _linha(no)))


def _parser(extensao: str) -> "Parser":
    linguagem = {
        "js": _tsjs.language,
        "ts": _tsts.language_typescript,
        "tsx": _tsts.language_tsx,
    }[extensao]
    return Parser(Language(linguagem()))


def analisar_ast_js(arquivo: str, fonte: str) -> ResultadoAst | None:
    """Resultado da análise de um arquivo JS/TS, ou None se não for possível (sem tree-sitter etc.)."""
    extensao = EXTENSOES_JS.get(PurePosixPath(arquivo).suffix)
    if not _DISPONIVEL or extensao is None:
        return None
    try:
        arvore = _parser(extensao).parse(fonte.encode("utf-8"))
        raiz = arvore.root_node
        arq = _arquivo(arquivo, raiz)
        achados: list = []
        _analisar_funcao_ou_modulo(raiz, set(), arq, achados, raiz_modulo=True)
        return ResultadoAst(achados, set())
    except (RecursionError, MemoryError, ValueError, UnicodeError):
        return None
