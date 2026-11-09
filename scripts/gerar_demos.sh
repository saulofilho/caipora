#!/usr/bin/env bash
# Regenera os relatórios de demonstração em docs/demos.
set -euo pipefail
cd "$(dirname "$0")/.."
d=docs/demos
mkdir -p "$d"

uv run caipora run examples/bot_vulneravel.py:responder -m base64,roleplay -o "$d/lgpd.html" --markdown "$d/lgpd.md" > /dev/null
uv run caipora run examples/agente_ingenuo.py:agente -p agente -o "$d/agente.html" --markdown "$d/agente.md" > /dev/null
uv run caipora mcp-auditar "python examples/mcp_envenenado.py" --chamar 'clima={"cidade": "Recife"}' \
  -o "$d/mcp.html" --markdown "$d/mcp.md" > /dev/null || true  # sai com 1 de propósito? não: sem --falhar-em sai 0

echo "demos geradas em $d"
