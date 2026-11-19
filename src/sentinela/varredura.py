"""Varre uma pasta inteira: cada arquivo de texto vira um trecho com todas as linhas "adicionadas"."""

import os
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
}
ARQUIVOS_IGNORADOS = [
    "*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
]
TAMANHO_MAXIMO = 1_000_000  # bytes; arquivos maiores costumam ser dados ou código gerado


def _tem_ast(nome: str) -> bool:
    return nome.endswith(".py") or Path(nome).suffix in EXTENSOES_JS


def _excluido(relativo: str, padroes: list[str]) -> bool:
    """Casa o caminho relativo com um padrão: glob, nome do arquivo ou prefixo de pasta."""
    nome = relativo.rsplit("/", 1)[-1]
    return any(
        fnmatch(relativo, p) or fnmatch(nome, p) or relativo.startswith(p.rstrip("/") + "/")
        for p in padroes
    )


def listar_arquivos(raiz: Path, excluir: list[str] | None = None) -> Iterator[Path]:
    """Percorre a pasta, pulando pastas de dependências, links simbólicos e caminhos excluídos."""
    excluir = excluir or []
    if raiz.is_file():
        yield raiz
        return

    for pasta, subpastas, arquivos in os.walk(raiz):
        relativa = Path(pasta).relative_to(raiz).as_posix()
        # Remove da lista in-place: o os.walk não desce nas pastas retiradas.
        subpastas[:] = sorted(
            s for s in subpastas
            if s not in PASTAS_IGNORADAS
            and not _excluido(s if relativa == "." else f"{relativa}/{s}", excluir)
        )
        for nome in sorted(arquivos):
            caminho = Path(pasta) / nome
            rel = caminho.relative_to(raiz).as_posix()
            if caminho.is_symlink() or _excluido(rel, excluir + ARQUIVOS_IGNORADOS):
                continue
            yield caminho


def ler_como_trecho(caminho: Path, raiz: Path) -> TrechoArquivo | None:
    """Lê um arquivo de texto. Devolve None para binários, arquivos grandes ou ilegíveis."""
    try:
        if caminho.stat().st_size > TAMANHO_MAXIMO:
            return None
        dados = caminho.read_bytes()
        if b"\0" in dados[:8000]:  # byte nulo: arquivo binário
            return None
        texto = dados.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    nome = caminho.name if raiz.is_file() else caminho.relative_to(raiz).as_posix()
    linhas = [LinhaAdicionada(i, t) for i, t in enumerate(texto.splitlines(), start=1)]
    fonte = texto if _tem_ast(nome) else None  # a análise por AST precisa do arquivo inteiro
    return TrechoArquivo(arquivo=nome, linhas_adicionadas=linhas, fonte=fonte)


def varrer(raiz: Path, excluir: list[str] | None = None) -> list[TrechoArquivo]:
    trechos = (ler_como_trecho(c, raiz) for c in listar_arquivos(raiz, excluir))
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
