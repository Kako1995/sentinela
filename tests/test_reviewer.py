import json
from pathlib import Path
from types import SimpleNamespace

from sentinela.diff import parse_diff
from sentinela.models import Severity
from sentinela.reviewer import Revisor

EXEMPLOS = Path(__file__).parent / "exemplos"

ACHADO = {
    "arquivo": "app/db.py",
    "linha": 14,
    "severidade": "alta",
    "categoria": "SQL injection",
    "cwe": "CWE-89",
    "explicacao": "A consulta concatena entrada do usuário.",
    "correcao": "Use parâmetros: conn.execute('... WHERE name = ?', (nome,)).",
}


class ClienteFalso:
    """Imita anthropic.Anthropic: devolve respostas prontas, sem chamar a API real."""

    def __init__(self, *textos: str):
        self.textos = list(textos)
        self.chamadas: list[dict] = []
        self.messages = self

    def create(self, **kwargs):
        self.chamadas.append(kwargs)
        texto = self.textos.pop(0)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=texto)],
            usage=SimpleNamespace(input_tokens=100, output_tokens=20),
        )


def trecho_simples():
    return parse_diff((EXEMPLOS / "simples.diff").read_text(encoding="utf-8"))[0]


def test_resposta_valida_vira_finding():
    cliente = ClienteFalso(json.dumps({"achados": [ACHADO]}))

    revisao = Revisor(client=cliente).revisar_trecho(trecho_simples())

    assert revisao.erros == []
    assert len(revisao.achados) == 1
    assert revisao.achados[0].severidade is Severity.alta
    assert revisao.achados[0].cwe == "CWE-89"
    assert len(cliente.chamadas) == 1


def test_mensagem_enviada_tem_arquivo_e_linhas_numeradas():
    cliente = ClienteFalso('{"achados": []}')

    Revisor(client=cliente).revisar_trecho(trecho_simples())

    mensagem = cliente.chamadas[0]["messages"][0]["content"]
    assert "Arquivo: app/db.py" in mensagem
    assert "14: " in mensagem and "SELECT * FROM users" in mensagem


def test_lista_vazia_e_codigo_seguro():
    revisao = Revisor(client=ClienteFalso('{"achados": []}')).revisar_trecho(trecho_simples())

    assert revisao.achados == [] and revisao.erros == []


def test_aceita_json_dentro_de_cerca_de_codigo():
    texto = "```json\n" + json.dumps({"achados": [ACHADO]}) + "\n```"

    revisao = Revisor(client=ClienteFalso(texto)).revisar_trecho(trecho_simples())

    assert len(revisao.achados) == 1


def test_resposta_invalida_tenta_de_novo_e_aceita_a_segunda():
    cliente = ClienteFalso("isto não é json", json.dumps({"achados": [ACHADO]}))

    revisao = Revisor(client=cliente).revisar_trecho(trecho_simples())

    assert len(cliente.chamadas) == 2
    assert len(revisao.achados) == 1 and revisao.erros == []
    # A nova tentativa mostra à IA o que deu errado.
    assert "inválida" in cliente.chamadas[1]["messages"][-1]["content"]


def test_duas_respostas_invalidas_registram_erro_sem_levantar_excecao():
    cliente = ClienteFalso("lixo", '{"achados": [{"arquivo": "x"}]}')

    revisao = Revisor(client=cliente).revisar_trecho(trecho_simples())

    assert len(cliente.chamadas) == 2
    assert revisao.achados == []
    assert len(revisao.erros) == 1 and "app/db.py" in revisao.erros[0]


def test_severidade_fora_do_enum_e_invalida():
    achado = {**ACHADO, "severidade": "gravissima"}
    cliente = ClienteFalso(json.dumps({"achados": [achado]}), json.dumps({"achados": [achado]}))

    revisao = Revisor(client=cliente).revisar_trecho(trecho_simples())

    assert revisao.achados == [] and len(revisao.erros) == 1


def test_tokens_sao_somados_entre_tentativas_e_arquivos():
    cliente = ClienteFalso("lixo", '{"achados": []}', '{"achados": []}')
    trechos = parse_diff((EXEMPLOS / "multiplos.diff").read_text(encoding="utf-8"))

    revisao = Revisor(client=cliente).revisar(trechos)

    # arquivo 1: 2 chamadas (1 inválida); arquivo 2: 1 chamada
    assert len(cliente.chamadas) == 3
    assert revisao.tokens_entrada == 300 and revisao.tokens_saida == 60
