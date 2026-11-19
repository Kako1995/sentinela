"""Quebra um diff unificado em trechos por arquivo."""

import re
from dataclasses import dataclass, field

CABECALHO_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class LinhaAdicionada:
    numero: int  # linha no arquivo novo
    texto: str


@dataclass
class TrechoArquivo:
    arquivo: str
    linhas_adicionadas: list[LinhaAdicionada] = field(default_factory=list)
    patch: str = ""  # texto bruto do diff desse arquivo, para mandar à IA depois


def _nome_arquivo(linha: str) -> str | None:
    """Extrai o caminho de uma linha '+++ b/caminho'. Retorna None para /dev/null."""
    caminho = linha[4:].split("\t")[0].strip()
    if caminho == "/dev/null":
        return None
    if caminho.startswith("b/"):
        caminho = caminho[2:]
    return caminho


def parse_diff(texto: str) -> list[TrechoArquivo]:
    """Separa o diff por arquivo, guardando as linhas adicionadas e seus números.

    Arquivos sem linhas adicionadas (removidos, binários, só renomeados) são
    ignorados, porque não há código novo para revisar.
    """
    trechos: list[TrechoArquivo] = []
    atual: TrechoArquivo | None = None
    linhas_patch: list[str] = []
    # Quantas linhas faltam ler no hunk atual (antigas, novas) e a próxima linha nova.
    faltam_antigas = faltam_novas = 0
    numero_novo = 0

    def fechar() -> None:
        if atual is not None and atual.linhas_adicionadas:
            atual.patch = "\n".join(linhas_patch) + "\n"
            trechos.append(atual)

    for linha in texto.splitlines():
        em_hunk = faltam_antigas > 0 or faltam_novas > 0

        if em_hunk:
            linhas_patch.append(linha)
            if linha.startswith("+"):
                if atual is not None:
                    atual.linhas_adicionadas.append(LinhaAdicionada(numero_novo, linha[1:]))
                numero_novo += 1
                faltam_novas -= 1
            elif linha.startswith("-"):
                faltam_antigas -= 1
            elif linha.startswith("\\"):  # "\ No newline at end of file"
                pass
            else:  # linha de contexto
                numero_novo += 1
                faltam_antigas -= 1
                faltam_novas -= 1
            continue

        if linha.startswith("diff --git "):
            fechar()
            atual, linhas_patch = None, [linha]
        elif linha.startswith("--- ") and atual is not None:
            # diff sem "diff --git" (ex.: `diff -u`): um novo "---" abre o próximo arquivo
            fechar()
            atual, linhas_patch = None, [linha]
        elif linha.startswith("+++ "):
            linhas_patch.append(linha)
            nome = _nome_arquivo(linha)
            atual = TrechoArquivo(arquivo=nome) if nome else None
        elif (m := CABECALHO_HUNK.match(linha)) and atual is not None:
            linhas_patch.append(linha)
            faltam_antigas = int(m.group(2) or 1)
            faltam_novas = int(m.group(4) or 1)
            numero_novo = int(m.group(3))
        else:
            linhas_patch.append(linha)

    fechar()
    return trechos
