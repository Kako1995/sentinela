"""Lê .sentinela.toml: regras desativadas e caminhos extras a ignorar numa varredura.

Arquivo opcional, na raiz do projeto (a pasta passada em `varrer` ou `--raiz`). Sem ele, com
sintaxe inválida, ou com um campo no formato errado, o Sentinela roda com o padrão de sempre
(todas as regras ativas, nada ignorado além do que já é padrão em varredura.py) — o arquivo de
configuração nunca derruba a ferramenta, só avisa (`Config.erro`) e segue sem ele.

Formato:

    [regras]
    desativar = ["segredo-url-com-senha", "tls-sem-verificacao"]

    [varrer]
    ignorar = ["migrations/", "*.generated.ts"]
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # backport: o parser só entrou na biblioteca padrão no 3.11

NOME_ARQUIVO = ".sentinela.toml"


@dataclass(frozen=True)
class Config:
    regras_desativadas: frozenset[str] = frozenset()
    ignorar: tuple[str, ...] = ()
    # Motivo pelo qual o arquivo foi ignorado (sintaxe inválida, campo no formato errado), se houver.
    # None quando não existe arquivo, ou quando ele foi lido com sucesso.
    erro: str | None = field(default=None, compare=False)


def _lista_de_strings(valor: object) -> list[str] | None:
    if not isinstance(valor, list) or not all(isinstance(x, str) for x in valor):
        return None
    return valor


def carregar(pasta: Path) -> Config:
    caminho = pasta / NOME_ARQUIVO
    if not caminho.is_file():
        return Config()
    try:
        dados = tomllib.loads(caminho.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        return Config(erro=f"sintaxe inválida ({e})")
    except (OSError, UnicodeDecodeError) as e:
        return Config(erro=f"não consegui ler o arquivo ({e})")

    avisos = []
    desativar = _lista_de_strings(dados.get("regras", {}).get("desativar", []))
    if desativar is None:
        avisos.append("regras.desativar precisa ser uma lista de texto")
        desativar = []
    ignorar = _lista_de_strings(dados.get("varrer", {}).get("ignorar", []))
    if ignorar is None:
        avisos.append("varrer.ignorar precisa ser uma lista de texto")
        ignorar = []

    return Config(
        regras_desativadas=frozenset(desativar),
        ignorar=tuple(ignorar),
        erro="; ".join(avisos) or None,
    )
