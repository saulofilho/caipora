#!/usr/bin/env bash
# Usado pela GitHub Action (action.yml). Recebe tudo por variáveis de ambiente
# (CAIPORA_*) para que nenhum input seja interpolado direto no shell.
set -uo pipefail

: "${CAIPORA_ALVO:?input 'alvo' é obrigatório}"
dir="${CAIPORA_DIR:-.}"
html="$dir/caipora-relatorio.html"
json="$dir/caipora-resultados.json"
md="$dir/caipora-resumo.md"

args=(run "$CAIPORA_ALVO" -p "${CAIPORA_PACOTE:-lgpd}" -o "$html" --json "$json" --markdown "$md")
[[ -n "${CAIPORA_MUTADORES:-}" ]] && args+=(-m "$CAIPORA_MUTADORES")
[[ -n "${CAIPORA_CATEGORIAS:-}" ]] && args+=(-c "$CAIPORA_CATEGORIAS")
[[ -n "${CAIPORA_LLM:-}" ]] && args+=(--llm "$CAIPORA_LLM")
[[ "${CAIPORA_FALHAR_SE_VULNERAVEL:-false}" == "true" ]] && args+=(--falhar-se-vulneravel)
[[ "${CAIPORA_FALHAR_SE_REGRESSAO:-true}" == "true" ]] && args+=(--falhar-se-regressao --tolerancia "${CAIPORA_TOLERANCIA:-0}")

if [[ -n "${CAIPORA_BASE:-}" ]]; then
  if [[ -f "$CAIPORA_BASE" ]]; then
    args+=(--base "$CAIPORA_BASE")
  else
    echo "::notice::linha de base '$CAIPORA_BASE' não encontrada; rodando sem comparação"
  fi
fi

if [[ -n "${CAIPORA_ARGS:-}" ]]; then
  read -r -a extra <<< "$CAIPORA_ARGS"
  args+=("${extra[@]}")
fi

${CAIPORA_CMD:-caipora} "${args[@]}"
code=$?

if [[ -f "$md" && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$md" >> "$GITHUB_STEP_SUMMARY"
fi
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "relatorio=$html"
    echo "resultados=$json"
    echo "resumo=$md"
    if [[ -f "$json" ]] && command -v jq >/dev/null; then
      echo "vulneraveis=$(jq '.resumo.por_status.vulneravel' "$json")"
      echo "regressoes=$(jq '.comparacao.regressoes // [] | length' "$json")"
    fi
  } >> "$GITHUB_OUTPUT"
fi
exit $code
