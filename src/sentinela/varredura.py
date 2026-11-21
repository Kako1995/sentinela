"""Varre uma pasta inteira: cada arquivo de texto vira um trecho com todas as linhas "adicionadas"."""

import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterator

from sentinela.ast_js import EXTENSOES_JS
from sentinela.diff import LinhaAdicionada, TrechoArquivo

# Pastas de dependências, builds e caches: código de terceiros ou gerado, não do projeto.
PASTAS_IGNORADAS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "dist", "build", ".next",
    ".nuxt", "target", "vendor", ".idea", ".vscode", "coverage",
    "_next",  # build do Next.js servido como estático (public/_next/...): bundles, nunca código do projeto
}
ARQUIVOS_IGNORADOS = [
    "*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "*.svg",  # imagem vetorial: costuma ser uma linha enorme e não tem código
    ".sentinela.toml",  # configuração da própria ferramenta, não código do projeto
]
# Markdown fica de fora por padrão (README e docs têm HTML e código de exemplo de propósito e geram alerta
# que não é do código do projeto), mas dá para incluir com `varrer --incluir-md`.
EXTENSOES_MARKDOWN = {".md", ".mdx"}
# Testes também ficam de fora por padrão: têm código vulnerável de propósito e credenciais de mentira, e num projeto
# real (Angular) testes e traduções somavam 281 dos 342 alertas (82%). Dá para incluir com `varrer --incluir-testes`.
# Uma pasta chamada `tests` passada como raiz é lida (foi pedida de propósito).
PASTAS_DE_TESTE = {"tests", "test", "__tests__", "__mocks__", "__snapshots__", "spec"}
_ARQUIVO_DE_TESTE = re.compile(r"(?:\.(?:spec|test)\.[cm]?[jt]sx?|_test\.(?:py|go))$|^test_.+\.py$|^conftest\.py$")
# Traduções: o valor de `"password": "Senha"` num JSON de idioma não é uma senha, e textos em tailandês ou japonês não
# têm espaço, então pareciam segredos (75 alertas falsos num único projeto real). Só os ARQUIVOS DE DADOS dessas pastas ficam
# de fora; código dentro delas (`i18n/index.ts`) continua sendo analisado. `varrer --incluir-traducoes` traz de volta.
PASTAS_DE_TRADUCAO = {"i18n", "l10n", "locales", "locale", "translations"}
EXTENSOES_DE_TRADUCAO = {
    ".json", ".yml", ".yaml", ".po", ".pot", ".properties", ".xlf", ".xliff", ".arb", ".ini", ".toml", ".csv", ".xml",
}
TAMANHO_MAXIMO = 1_000_000  # bytes; arquivos maiores costumam ser dados ou código gerado

# Por que um arquivo ou pasta não foi analisado (aparece na saída do `varrer`).
MOTIVO_MARKDOWN = "Markdown (.md/.mdx)"
MOTIVO_SVG = "SVG"
MOTIVO_TESTE = "arquivo ou pasta de teste"
MOTIVO_TRADUCAO = "arquivo de tradução (i18n)"
MOTIVO_GERADO = "minificado, mapa ou lockfile"
MOTIVO_PASTA = "pasta de dependências ou build"
MOTIVO_EXCLUIDO = "excluído por -x ou pelo .sentinela.toml"
MOTIVO_GRANDE = f"maior que {TAMANHO_MAXIMO // 1_000_000} MB"
MOTIVO_BINARIO = "binário ou ilegível (não é texto UTF-8)"
MOTIVO_LINK = "link simbólico"
ARQUIVO_DE_CONFIGURACAO = ".sentinela.toml"  # pulado em silêncio: não é algo que o usuário "perdeu"
PASTAS_SILENCIOSAS = {".git", ".hg", ".svn", ".idea", ".vscode"}  # controle de versão e editor: sempre ruído no aviso


@dataclass
class Pulados:
    """O que o `varrer` não analisou, agrupado pelo motivo. Serve só para avisar o usuário."""

    por_motivo: dict[str, list[str]] = field(default_factory=dict)

    def adicionar(self, motivo: str, caminho: str) -> None:
        self.por_motivo.setdefault(motivo, []).append(caminho)

    def total(self) -> int:
        return sum(len(v) for v in self.por_motivo.values())


def _tem_ast(nome: str) -> bool:
    return nome.endswith(".py") or Path(nome).suffix in EXTENSOES_JS


def _excluido(relativo: str, padroes: list[str]) -> bool:
    """Casa o caminho relativo com um padrão: glob, nome do arquivo ou prefixo de pasta."""
    nome = relativo.rsplit("/", 1)[-1]
    return any(
        fnmatch(relativo, p) or fnmatch(nome, p) or relativo.startswith(p.rstrip("/") + "/")
        for p in padroes
    )


def _motivo_de_pular_arquivo(
    rel: str, excluir: list[str], incluir_markdown: bool, incluir_testes: bool = True, incluir_traducoes: bool = True
) -> str | None:
    """Por que um arquivo não deve ser lido (None = deve ser lido)."""
    if _excluido(rel, excluir):
        return MOTIVO_EXCLUIDO
    if not incluir_markdown and Path(rel).suffix.lower() in EXTENSOES_MARKDOWN:
        return MOTIVO_MARKDOWN
    nome = rel.rsplit("/", 1)[-1]
    if not incluir_testes and _ARQUIVO_DE_TESTE.search(nome):
        return MOTIVO_TESTE
    pastas = rel.split("/")[:-1]
    if not incluir_traducoes and Path(rel).suffix.lower() in EXTENSOES_DE_TRADUCAO and PASTAS_DE_TRADUCAO.intersection(pastas):
        return MOTIVO_TRADUCAO
    if rel.rsplit("/", 1)[-1] == ARQUIVO_DE_CONFIGURACAO:
        return ARQUIVO_DE_CONFIGURACAO  # só um marcador: quem chama não registra esse
    if _excluido(rel, ARQUIVOS_IGNORADOS):
        return MOTIVO_SVG if Path(rel).suffix.lower() == ".svg" else MOTIVO_GERADO
    return None


def listar_arquivos(
    raiz: Path,
    excluir: list[str] | None = None,
    incluir_markdown: bool = False,
    pulados: Pulados | None = None,
    incluir_testes: bool = False,
    incluir_traducoes: bool = False,
) -> Iterator[Path]:
    """Percorre a pasta, pulando pastas de dependências, links simbólicos e caminhos excluídos.

    Também pula Markdown, testes e arquivos de tradução, a não ser que `incluir_*` peça o contrário.
    Se `pulados` for dado, anota nele o que foi deixado de fora e por quê.
    """
    excluir = excluir or []
    if raiz.is_file():
        yield raiz
        return
    # Quem aponta o varrer para a própria pasta de testes (ou de traduções) pediu para lê-la.
    incluir_testes = incluir_testes or raiz.resolve().name in PASTAS_DE_TESTE
    incluir_traducoes = incluir_traducoes or raiz.resolve().name in PASTAS_DE_TRADUCAO

    for pasta, subpastas, arquivos in os.walk(raiz):
        relativa = Path(pasta).relative_to(raiz).as_posix()
        mantidas = []
        for s in sorted(subpastas):
            rel_sub = s if relativa == "." else f"{relativa}/{s}"
            if s in PASTAS_IGNORADAS:
                motivo = MOTIVO_PASTA
            elif s in PASTAS_DE_TESTE and not incluir_testes:
                motivo = MOTIVO_TESTE
            elif _excluido(rel_sub, excluir):
                motivo = MOTIVO_EXCLUIDO
            else:
                mantidas.append(s)
                continue
            if pulados is not None and s not in PASTAS_SILENCIOSAS:
                pulados.adicionar(motivo, rel_sub)
        # Remove da lista in-place: o os.walk não desce nas pastas retiradas.
        subpastas[:] = mantidas
        for nome in sorted(arquivos):
            caminho = Path(pasta) / nome
            rel = caminho.relative_to(raiz).as_posix()
            motivo = (
                MOTIVO_LINK
                if caminho.is_symlink()
                else _motivo_de_pular_arquivo(rel, excluir, incluir_markdown, incluir_testes, incluir_traducoes)
            )
            if motivo is None:
                yield caminho
            elif pulados is not None and motivo != ARQUIVO_DE_CONFIGURACAO:
                pulados.adicionar(motivo, rel)


def ler_como_trecho(caminho: Path, raiz: Path, pulados: Pulados | None = None) -> TrechoArquivo | None:
    """Lê um arquivo de texto. Devolve None para binários, arquivos grandes ou ilegíveis."""
    nome = caminho.name if raiz.is_file() else caminho.relative_to(raiz).as_posix()
    try:
        if caminho.stat().st_size > TAMANHO_MAXIMO:
            if pulados is not None:
                pulados.adicionar(MOTIVO_GRANDE, nome)
            return None
        dados = caminho.read_bytes()
        # byte nulo: arquivo binário
        texto = None if b"\0" in dados[:8000] else dados.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        texto = None
    if texto is None:
        if pulados is not None:
            pulados.adicionar(MOTIVO_BINARIO, nome)
        return None

    linhas = [LinhaAdicionada(i, t) for i, t in enumerate(texto.splitlines(), start=1)]
    fonte = texto if _tem_ast(nome) else None  # a análise por AST precisa do arquivo inteiro
    return TrechoArquivo(arquivo=nome, linhas_adicionadas=linhas, fonte=fonte)


def varrer(
    raiz: Path,
    excluir: list[str] | None = None,
    incluir_markdown: bool = False,
    pulados: Pulados | None = None,
    incluir_testes: bool = False,
    incluir_traducoes: bool = False,
) -> list[TrechoArquivo]:
    arquivos = listar_arquivos(raiz, excluir, incluir_markdown, pulados, incluir_testes, incluir_traducoes)
    trechos = (ler_como_trecho(c, raiz, pulados) for c in arquivos)
    return [t for t in trechos if t is not None]


def anexar_fontes(trechos: list[TrechoArquivo], raiz: Path) -> int:
    """Lê do disco o arquivo completo de cada .py/.js/.ts de um diff, para a análise por AST.

    O nome do arquivo vem do diff, que pode ser de um PR malicioso (`+++ b/../../etc/x.py`), então:
    só lê arquivos que, depois de resolvidos, ficam DENTRO de `raiz`, que não são links simbólicos
    e que não passam do tamanho máximo. E só usa o arquivo se ele bate com o diff: as linhas
    adicionadas precisam ser idênticas às do disco (senão é outro checkout e os números de linha
    dos achados sairiam errados). Devolve quantos desses arquivos ficaram sem análise por AST.
    """
    base = raiz.resolve()
    ignorados = 0
    for trecho in trechos:
        if not _tem_ast(trecho.arquivo):
            continue
        alvo = base / trecho.arquivo
        try:
            if alvo.is_symlink() or not alvo.resolve().is_relative_to(base) or not alvo.is_file():
                raise OSError("fora da raiz, link simbólico ou inexistente")
            if alvo.stat().st_size > TAMANHO_MAXIMO:
                raise OSError("arquivo grande demais")
            texto = alvo.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            ignorados += 1
            continue
        linhas = texto.splitlines()
        if all(l.numero <= len(linhas) and linhas[l.numero - 1] == l.texto for l in trecho.linhas_adicionadas):
            trecho.fonte = texto
        else:
            ignorados += 1
    return ignorados
