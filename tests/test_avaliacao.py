from pathlib import Path

import pytest

from sentinela.avaliacao import (
    Caso,
    avaliar_caso,
    calcular_metricas,
    carregar_casos,
    recall_por_categoria,
)

PASTA_CASOS = Path(__file__).parent.parent / "evals" / "casos"


def caso(codigo: str, vulneravel: bool, categoria: str | None = None) -> Caso:
    return Caso(id="x", linguagem="python", codigo=codigo, vulneravel=vulneravel, categoria_esperada=categoria)


MD5 = "h = hashlib.md5(senha)"
SEGURO = "h = hashlib.sha256(senha)"


def test_vulneravel_com_categoria_certa_e_tp():
    r = avaliar_caso(caso(MD5, True, "criptografia fraca"))

    assert r.veredito == "TP" and r.categorias_achadas == ["criptografia fraca"]


def test_vulneravel_sem_achados_e_fn():
    assert avaliar_caso(caso(SEGURO, True, "criptografia fraca")).veredito == "FN"


def test_vulneravel_com_categoria_errada_e_fn():
    r = avaliar_caso(caso(MD5, True, "SQL injection"))

    assert r.veredito == "FN" and r.categorias_achadas == ["criptografia fraca"]


def test_seguro_com_achado_e_fp():
    assert avaliar_caso(caso(MD5, False)).veredito == "FP"


def test_seguro_sem_achados_e_tn():
    assert avaliar_caso(caso(SEGURO, False)).veredito == "TN"


def test_precisao_e_recall():
    resultados = [
        avaliar_caso(caso(MD5, True, "criptografia fraca")),  # TP
        avaliar_caso(caso(MD5, True, "criptografia fraca")),  # TP
        avaliar_caso(caso(SEGURO, True, "criptografia fraca")),  # FN
        avaliar_caso(caso(MD5, False)),  # FP
        avaliar_caso(caso(SEGURO, False)),  # TN
    ]

    m = calcular_metricas(resultados)

    assert (m.tp, m.fp, m.fn, m.tn) == (2, 1, 1, 1)
    assert m.precisao == pytest.approx(2 / 3)  # 2 dos 3 alertas eram reais
    assert m.recall == pytest.approx(2 / 3)  # 2 das 3 vulnerabilidades foram achadas


def test_metricas_sem_divisao_por_zero():
    m = calcular_metricas([avaliar_caso(caso(SEGURO, False))])

    assert m.precisao is None and m.recall is None


def test_recall_por_categoria():
    resultados = [
        avaliar_caso(caso(MD5, True, "criptografia fraca")),
        avaliar_caso(caso(SEGURO, True, "criptografia fraca")),
        avaliar_caso(caso(SEGURO, False)),
    ]

    assert recall_por_categoria(resultados) == {"criptografia fraca": (1, 2)}


def test_rotulo_incoerente_e_rejeitado():
    with pytest.raises(ValueError):
        caso("x = 1", True)  # vulnerável sem categoria
    with pytest.raises(ValueError):
        caso("x = 1", False, "XSS")  # seguro com categoria


def test_casos_iniciais_estao_validos_e_balanceados():
    casos = [c for c in carregar_casos(PASTA_CASOS) if c.origem == "claude"]

    assert sum(c.vulneravel for c in casos) == 20
    assert sum(not c.vulneravel for c in casos) == 10
    assert len({c.id for c in casos}) == 30
