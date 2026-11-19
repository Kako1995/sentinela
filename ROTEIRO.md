# Sentinela: roteiro de construção

## Por que esse projeto

Ele nasce da conversa de hoje: a IA gera código rápido, mas alguém precisa saber se esse código é seguro. O Sentinela é uma ferramenta que faz essa revisão, e o Carlos é quem entende, mede e melhora ela.

Numa entrevista, ele mostra de uma vez:

- **IA aplicada:** prompt, saída estruturada, validação, custo
- **Segurança:** OWASP Top 10, CWE, vulnerabilidades reais
- **Backend/CLI:** Python, testes, empacotamento
- **Engenharia de verdade:** evals (medir se a IA acerta), CI/CD
- **Produto:** usuários reais (devs open source usando a Action)

O diferencial são os **evals**. Quase ninguém em nível de estágio mostra que sabe medir se a IA está certa. É exatamente o que empresas de IA procuram.

## Preparação (30 min)

```bash
mkdir sentinela && cd sentinela
git init
# copiar o CLAUDE.md para a raiz
python -m venv .venv && source .venv/bin/activate
claude
```

Pegar uma chave em console.anthropic.com e colocar no `.env`:

```bash
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
echo ".env" >> .gitignore
```

---

## Fase 1: esqueleto e leitura de diff (1 a 2 dias)

**Prompt no Claude Code:**
```
Leia o CLAUDE.md. Crie o esqueleto do projeto: pyproject.toml, pacote sentinela,
CLI com Typer e um comando "revisar" que lê um diff de arquivo ou stdin.
Implemente diff.py que quebra um diff unificado em trechos por arquivo,
guardando nome do arquivo, linhas adicionadas e número da linha.
Escreva testes com 3 diffs de exemplo. Ainda sem IA.
```

**Carlos precisa saber explicar:** o que é um diff unificado, por que separar por arquivo, como o Typer transforma função em comando.

## Fase 2: chamada à IA com saída estruturada (2 a 3 dias)

**Prompt:**
```
Implemente models.py com Finding e Severity em Pydantic, seguindo o formato do CLAUDE.md.
Implemente reviewer.py: envia cada trecho do diff para a API da Anthropic com o prompt
de sistema de prompts.py e exige resposta em JSON validado pelo Pydantic.
Se a resposta vier inválida, tenta de novo uma vez e depois registra o erro.
Nos testes, use mock da API, sem chamada real.
```

**Carlos precisa saber explicar:** por que validar a saída da IA, o que é mock e por que testes não chamam a API real, quanto custa cada revisão (tokens).

## Fase 3: relatório (1 dia)

**Prompt:**
```
Implemente report.py com três formatos: terminal (Rich, colorido por severidade),
markdown (para comentário de PR) e JSON. Adicione a flag --formato.
O comando deve sair com código 1 se houver achado de severidade alta ou crítica.
```

**Carlos precisa saber explicar:** exit code e por que ele importa pro CI.

## Fase 4: evals, a parte mais importante (3 a 4 dias)

**Prompt:**
```
Crie evals/casos/ com 30 casos rotulados em JSON: 20 trechos vulneráveis
(SQL injection, XSS, segredo no código, path traversal, desserialização insegura,
SSRF, falta de autorização) e 10 trechos seguros parecidos com os vulneráveis.
Cada caso tem: codigo, linguagem, vulneravel (bool), categoria_esperada.
Implemente run_evals.py que roda o revisor em todos e mostra precisão, recall
e uma tabela dos erros. Salve o resultado em evals/resultados/ com data.
```

Depois, **sem IA**: o Carlos escreve à mão mais 10 casos difíceis (código seguro que parece perigoso e vice-versa). Isso mostra critério próprio.

Em seguida, iterar no prompt de `prompts.py` e comparar os números antes e depois. Guardar cada versão.

**Carlos precisa saber explicar:** diferença entre precisão e recall, por que falso positivo irrita o usuário, como ele melhorou o prompt e quanto melhorou.

## Fase 5: GitHub Action (1 a 2 dias)

**Prompt:**
```
Crie .github/workflows/sentinela.yml que roda o Sentinela em todo pull request,
pega o diff contra a branch base e posta o relatório markdown como comentário no PR.
A chave vem de secrets.ANTHROPIC_API_KEY. Documente no README como outra pessoa
instala a Action no repositório dela.
```

**Carlos precisa saber explicar:** como o GitHub Actions funciona, o que são secrets, permissões do token.

## Fase 6: README e usuários reais (contínuo)

- README com GIF do terminal, tabela de resultados dos evals e decisões técnicas
- Seção "Limitações": o que o Sentinela não pega (isso conta pontos, mostra maturidade)
- Publicar e pedir pra 3 a 5 colegas da PUCRS usarem nos projetos deles
- Abrir 1 ou 2 issues reais a partir do feedback e resolver

---

## Extras se sobrar fôlego

- Cache de resultados para não pagar duas vezes pelo mesmo trecho
- Contexto extra: mandar o arquivo inteiro além do diff para reduzir falso positivo
- Modo `--corrigir` que aplica a correção sugerida e roda os testes
- Comparar dois modelos nos evals (custo x acerto)

## Como apresentar na entrevista (2 minutos)

1. **Problema:** IA gera código rápido, mas ninguém revisa a segurança com o mesmo ritmo.
2. **Solução:** revisor que roda em todo PR e explica o problema em português.
3. **Como sei que funciona:** 40 casos rotulados, precisão X%, recall Y%, melhorei Z pontos ajustando o prompt.
4. **O que aprendi:** onde a IA erra, por que validação e evals importam.
5. **Limitações:** o que ele não pega e o que eu faria a seguir.

## Regra de ouro

Se o Carlos não consegue explicar uma parte do código sem olhar, ele pede pro Claude Code explicar, reescreve com as palavras dele num comentário e só então segue. O projeto vale pelo que ele entende, não pelo que foi gerado.
