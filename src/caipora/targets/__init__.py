"""Alvos: a aplicação sob teste.

Todo alvo implementa `Target`. Novos tipos (MCP, agente em honeypot) entram
aqui sem mudar o resto da ferramenta.
"""

from __future__ import annotations

from typing import Any

from .base import Target, Turn
from .callback import CallbackTarget
from .http import HttpTarget

__all__ = ["Target", "Turn", "CallbackTarget", "HttpTarget", "build_target"]


def build_target(spec: str, **http_options: Any) -> Target:
    """`http(s)://...` vira HttpTarget; `modulo:funcao` ou `arquivo.py:funcao` vira CallbackTarget."""
    if spec.startswith(("http://", "https://")):
        return HttpTarget(spec, **http_options)
    return CallbackTarget(spec)
