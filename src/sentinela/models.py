from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    baixa = "baixa"
    media = "media"
    alta = "alta"
    critica = "critica"


# Achados nessas severidades fazem o comando sair com código 1 (e falhar o CI).
BLOQUEANTES = {Severity.alta, Severity.critica}


class Finding(BaseModel):
    arquivo: str
    linha: int  # linha no arquivo novo
    severidade: Severity
    categoria: str  # ex.: "SQL injection", "XSS", "segredo no código"
    cwe: str | None = None  # ex.: "CWE-89"
    regra: str  # id da regra que disparou, ex.: "sql-concatenacao"
    explicacao: str  # em português, curta e específica
    correcao: str  # sugestão concreta
