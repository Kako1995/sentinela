#!/usr/bin/env bash
# Roda o Sentinela no diff de um pull request, publica o relatório e sai com o código dele.
#
# Variáveis de ambiente:
#   BASE_SHA, HEAD_SHA        commits do PR (obrigatórios)
#   EXCLUIR                   caminhos a ignorar, separados por espaço (opcional)
#   GH_TOKEN, REPO, PR_NUMBER para comentar no PR (opcionais; sem eles só imprime o relatório)
set -uo pipefail

if [ -z "${BASE_SHA:-}" ] || [ -z "${HEAD_SHA:-}" ]; then
  echo "::error::Esta Action só roda em eventos pull_request."
  exit 2
fi

RELATORIO="${RELATORIO:-sentinela-relatorio.md}"
DIFF="$(mktemp)"

# Caminhos excluídos viram pathspecs do git (":(exclude)caminho").
read -ra partes <<< "${EXCLUIR:-}"
excluir=()
for caminho in ${partes[@]+"${partes[@]}"}; do
  excluir+=(":(exclude)$caminho")
done

# Se o git não achar os commits (checkout raso), o diff sairia vazio e o PR passaria
# sem ser revisado. Por isso um erro aqui falha o job em vez de parecer "sem problemas".
if ! git diff --no-color "$BASE_SHA...$HEAD_SHA" -- . ${excluir[@]+"${excluir[@]}"} > "$DIFF"; then
  echo "::error::Não foi possível calcular o diff. Use actions/checkout com fetch-depth: 0 antes desta Action."
  exit 2
fi

# --raiz .: lê os .py inteiros do checkout, para a análise por AST (o diff sozinho só tem as linhas novas)
sentinela revisar "$DIFF" --formato markdown --raiz . > "$RELATORIO"
codigo=$?

cat "$RELATORIO"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$RELATORIO" >> "$GITHUB_STEP_SUMMARY"
fi

# Atualiza o comentário anterior do Sentinela (achado pelo marcador) ou cria um novo.
publicar_comentario() {
  local existente
  existente=$(gh api "repos/$REPO/issues/$PR_NUMBER/comments" --paginate \
    --jq '.[] | select(.body | contains("<!-- sentinela -->")) | .id' | head -n 1)
  if [ -n "$existente" ]; then
    gh api -X PATCH "repos/$REPO/issues/comments/$existente" -F body=@"$RELATORIO" > /dev/null
  else
    gh api -X POST "repos/$REPO/issues/$PR_NUMBER/comments" -F body=@"$RELATORIO" > /dev/null
  fi
}

if [ -n "${GH_TOKEN:-}" ] && [ -n "${REPO:-}" ] && [ -n "${PR_NUMBER:-}" ]; then
  # PRs vindos de forks recebem um token somente leitura: o comentário falha, mas o
  # relatório continua no resumo do job e o resultado da revisão não muda.
  publicar_comentario || echo "::warning::Não foi possível comentar no PR (sem permissão, ou PR de fork). O relatório está no resumo do job."
fi

exit "$codigo"
