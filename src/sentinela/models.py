from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    baixa = "baixa"
    media = "media"
    alta = "alta"
    critica = "critica"


class Finding(BaseModel):
    arquivo: str
    linha: int  # linha no arquivo novo
    severidade: Severity
    categoria: str  # ex.: "SQL injection", "XSS", "segredo no código"
    cwe: str | None = None  # ex.: "CWE-89"
    explicacao: str  # em português, curta e específica
    correcao: str  # sugestão concreta


class RespostaIA(BaseModel):
    """Formato exato que a IA deve devolver: um objeto com a lista de achados."""

    achados: list[Finding]
