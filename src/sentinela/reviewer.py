"""Envia cada trecho do diff à API da Anthropic e valida a resposta com Pydantic."""

import json
import os
import re
from dataclasses import dataclass, field

import anthropic
from pydantic import ValidationError

from sentinela.diff import TrechoArquivo
from sentinela.models import Finding, RespostaIA
from sentinela.prompts import SYSTEM_PROMPT, montar_mensagem_usuario

MODELO_PADRAO = "claude-sonnet-5-5"
MAX_TOKENS = 2000
TENTATIVAS = 2  # a primeira + uma nova tentativa se a resposta vier inválida


@dataclass
class Revisao:
    achados: list[Finding] = field(default_factory=list)
    erros: list[str] = field(default_factory=list)
    tokens_entrada: int = 0
    tokens_saida: int = 0


def _extrair_json(texto: str) -> str:
    """Tira cercas de código (```json ... ```) caso o modelo as adicione mesmo sem pedir."""
    m = re.search(r"```(?:json)?\s*(.*?)```", texto, re.DOTALL)
    return (m.group(1) if m else texto).strip()


def _validar(texto: str) -> list[Finding]:
    return RespostaIA.model_validate(json.loads(_extrair_json(texto))).achados


class Revisor:
    def __init__(self, client: anthropic.Anthropic | None = None, modelo: str | None = None):
        self.client = client or anthropic.Anthropic()
        self.modelo = modelo or os.environ.get("SENTINELA_MODELO", MODELO_PADRAO)

    def revisar_trecho(self, trecho: TrechoArquivo) -> Revisao:
        """Revisa um arquivo. Resposta inválida: tenta de novo uma vez e depois registra o erro."""
        resultado = Revisao()
        mensagens = [
            {
                "role": "user",
                "content": montar_mensagem_usuario(
                    trecho.arquivo,
                    trecho.patch,
                    [(l.numero, l.texto) for l in trecho.linhas_adicionadas],
                ),
            }
        ]

        for tentativa in range(TENTATIVAS):
            resposta = self.client.messages.create(
                model=self.modelo,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=mensagens,
            )
            resultado.tokens_entrada += resposta.usage.input_tokens
            resultado.tokens_saida += resposta.usage.output_tokens
            texto = "".join(b.text for b in resposta.content if b.type == "text")

            try:
                resultado.achados = _validar(texto)
                return resultado
            except (json.JSONDecodeError, ValidationError) as erro:
                if tentativa + 1 < TENTATIVAS:
                    mensagens += [
                        {"role": "assistant", "content": texto},
                        {
                            "role": "user",
                            "content": f"Sua resposta é inválida ({erro}). "
                            "Responda de novo SOMENTE com o JSON no formato pedido.",
                        },
                    ]
                else:
                    resultado.erros.append(f"{trecho.arquivo}: resposta inválida da IA: {erro}")
        return resultado

    def revisar(self, trechos: list[TrechoArquivo]) -> Revisao:
        """Revisa todos os arquivos e soma achados, erros e tokens."""
        total = Revisao()
        for trecho in trechos:
            parcial = self.revisar_trecho(trecho)
            total.achados += parcial.achados
            total.erros += parcial.erros
            total.tokens_entrada += parcial.tokens_entrada
            total.tokens_saida += parcial.tokens_saida
        return total
