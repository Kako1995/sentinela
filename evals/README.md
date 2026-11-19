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
  "codigo": "linha 1\nlinha 2"
}
```

- Caso seguro: `"vulneravel": false` e `"categoria_esperada": null`.
- Categorias: SQL injection, XSS, segredo no código, path traversal, desserialização insegura, SSRF, injeção de comando, falta de autorização, criptografia fraca.
- Use `"origem": "carlos"` nos casos escritos à mão, para os números deles aparecerem separados.

## Como os números são calculados

Por caso, não por linha. Vulnerável é a classe positiva.

- **TP:** caso vulnerável em que o scanner achou a categoria esperada.
- **FN:** caso vulnerável em que ele não achou (ou achou só outra categoria).
- **FP:** caso seguro em que ele achou algo.
- **TN:** caso seguro sem achados.
- **Precisão** = TP / (TP + FP). **Recall** = TP / (TP + FN).
