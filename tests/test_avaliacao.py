from pathlib import Path

import pytest

from sentinela.avaliacao import (
    Caso,
    avaliar,
    avaliar_caso,
    calcular_metricas,
    carregar_casos,
    comparar_com_baseline,
    ler_baseline,
    recall_por_categoria,
    serializar_baseline,
    veredito_por_caso,
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


# --- trava de regressão: comparar os vereditos de cada caso com a baseline versionada ---

PASTA_EVALS = Path(__file__).parent.parent / "evals"


def test_baseline_igual_ao_resultado_nao_tem_diferenca():
    base = {"a": "TP", "b": "TN", "c": "FN"}

    d = comparar_com_baseline(base, dict(base))

    assert not d.quebrou and not d.desatualizada


@pytest.mark.parametrize("antes, agora", [("TP", "FN"), ("TN", "FP")])
def test_acerto_que_vira_erro_e_regressao(antes, agora):
    d = comparar_com_baseline({"a": antes}, {"a": agora})

    assert d.quebrou and d.regressoes == [("a", antes, agora)]


def test_caso_que_sumiu_quebra_a_trava():
    """Apagar ou renomear um caso poderia esconder uma regressão: tem que ser decisão visível."""
    d = comparar_com_baseline({"a": "TP", "b": "TN"}, {"a": "TP"})

    assert d.quebrou and d.removidos == ["b"]


def test_erro_que_vira_acerto_e_melhoria_mas_pede_atualizar_a_baseline():
    d = comparar_com_baseline({"a": "FN", "b": "FP"}, {"a": "TP", "b": "TN"})

    assert not d.quebrou and d.desatualizada
    assert d.melhorias == [("a", "FN", "TP"), ("b", "FP", "TN")]


def test_caso_novo_nao_quebra_mas_pede_atualizar_a_baseline_mesmo_se_for_erro():
    d = comparar_com_baseline({"a": "TP"}, {"a": "TP", "novo": "FN"})

    assert not d.quebrou and d.desatualizada and d.novos == [("novo", "FN")]


def test_erro_conhecido_que_continua_erro_nao_e_regressao():
    d = comparar_com_baseline({"a": "FN"}, {"a": "FN"})

    assert not d.quebrou and not d.desatualizada


def test_mudanca_de_acerto_para_acerto_e_so_atualizacao():
    """Ex.: o rótulo do caso mudou (TP -> TN). Não é regressão, mas a baseline precisa registrar."""
    d = comparar_com_baseline({"a": "TP"}, {"a": "TN"})

    assert not d.quebrou and d.desatualizada and d.outras == [("a", "TP", "TN")]


def test_serializar_baseline_e_estavel_ordenado_e_sem_data():
    r = avaliar([
        Caso(id="b", linguagem="python", codigo=SEGURO, vulneravel=False),
        Caso(id="a", linguagem="python", codigo=MD5, vulneravel=True, categoria_esperada="criptografia fraca"),
    ])

    texto = serializar_baseline(r)

    assert texto == serializar_baseline(list(reversed(r)))  # não depende da ordem de leitura dos arquivos
    assert ler_baseline(texto) == {"a": "TP", "b": "TN"}
    assert texto.index('"a"') < texto.index('"b"')
    assert "data" not in texto and "commit" not in texto  # sem ruído de diff entre rodadas


def test_baseline_versionada_bate_com_os_evals_de_hoje():
    """É a mesma checagem do CI, rodando junto do pytest: se uma regra piorar um caso, ou se casos mudarem sem
    atualizar evals/baseline.json, isto falha localmente também."""
    atual = veredito_por_caso(avaliar(carregar_casos(PASTA_EVALS / "casos")))
    baseline = ler_baseline((PASTA_EVALS / "baseline.json").read_text(encoding="utf-8"))

    d = comparar_com_baseline(baseline, atual)

    assert not d.quebrou, f"REGRESSÃO nos evals: {d.regressoes} (casos removidos: {d.removidos})"
    assert not d.desatualizada, (
        "evals/baseline.json está desatualizada em relação aos casos/regras. Rode "
        "`python evals/run_evals.py --atualizar-baseline` e commite o resultado."
    )
