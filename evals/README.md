# Evals

Medem quão bem o scanner acerta, em casos rotulados.

```bash
python evals/run_evals.py --rotulo nome-da-rodada
```

Cada rodada é salva em `resultados/` com data, rótulo e commit, para comparar antes e depois de mudar as regras.

## Como adicionar um caso

Crie um arquivo `.json` em `casos/` (o nome do arquivo vira o id do caso):

```json
{
  "linguagem": "python",
  "vulneravel": true,
  "categoria_esperada": "SQL injection",
  "origem": "carlos",
  "nota": "por que este caso é difícil",
  "codigo": "linha 1\nlinha 2"
}
```

- Caso seguro: `"vulneravel": false` e `"categoria_esperada": null`.
- Categorias: SQL injection, XSS, segredo no código, path traversal, desserialização insegura, SSRF, injeção de comando, falta de autorização, criptografia fraca, exposição de rede, autenticação fraca.
- `"origem"` separa os números por quem escreveu o caso: `claude` (30 iniciais), `claude-dificil` (10 difíceis) e `carlos` (casos escritos à mão por você).
- `"nota"` é opcional: por que o caso é difícil.
- `"arquivo"` é opcional: o nome do arquivo de verdade, quando ele importa para a análise (ex.: `app/api/x/route.ts` é um route handler do Next.js; sem isso o arquivo se chama como o caso).

## Como os números são calculados

Por caso, não por linha. Vulnerável é a classe positiva.

- **TP:** caso vulnerável em que o scanner achou a categoria esperada.
- **FN:** caso vulnerável em que ele não achou (ou achou só outra categoria).
- **FP:** caso seguro em que ele achou algo.
- **TN:** caso seguro sem achados.
- **Precisão** = TP / (TP + FP). **Recall** = TP / (TP + FN).

## Trava de regressão (baseline)

`baseline.json` guarda o veredito (TP, TN, FP ou FN) de cada caso. O CI e o `pytest` comparam a rodada de agora com ele:

```bash
python evals/run_evals.py --verificar            # compara com a baseline
python evals/run_evals.py --atualizar-baseline   # grava a rodada de agora como a nova baseline
```

| Código de saída | Significa | Reprova o CI? |
|---|---|---|
| 0 | Nenhum caso mudou. | não |
| 1 | **Regressão**: um acerto (TP/TN) virou erro (FN/FP), ou um caso sumiu (apagado ou renomeado). | **sim** |
| 2 | Nada piorou, mas a baseline está **desatualizada**: melhorias (erro que virou acerto), casos novos, ou rótulo que mudou. | **sim** |

O código 2 reprova de propósito: assim `baseline.json` é sempre a fotografia de hoje, e o diff dela em cada PR mostra exatamente quais casos mudaram de veredito. Um caso que já era erro e continua erro (uma fraqueza conhecida e documentada) **não** reprova. Quando uma mudança de regra piora um caso de propósito, justifique no PR e atualize a baseline.
