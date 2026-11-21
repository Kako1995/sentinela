from sentinela.models import Finding, Severity
from sentinela.report import calcular_nota


def _achado(severidade: Severity) -> Finding:
    return Finding(
        arquivo="a.py", linha=1, severidade=severidade, categoria="x",
        regra="x", explicacao="x", correcao="x",
    )


def test_nota_sem_achados_e_10():
    assert calcular_nota([]) == 10.0


def test_nota_tira_peso_certo_por_severidade():
    assert calcular_nota([_achado(Severity.critica)]) == 7.0
    assert calcular_nota([_achado(Severity.alta)]) == 8.0
    assert calcular_nota([_achado(Severity.media)]) == 9.0
    assert calcular_nota([_achado(Severity.baixa)]) == 9.5


def test_nota_soma_varios_achados():
    achados = [_achado(Severity.alta), _achado(Severity.media), _achado(Severity.media)]
    assert calcular_nota(achados) == 6.0  # 10 - (2 + 1 + 1)


def test_nota_nunca_fica_negativa():
    achados = [_achado(Severity.critica) for _ in range(10)]  # bem mais que o suficiente pra passar de 0
    assert calcular_nota(achados) == 0.0
