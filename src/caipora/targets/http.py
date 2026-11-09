from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from .base import Turn

PLACEHOLDER = "{prompt}"


def fill_template(node: Any, prompt: str) -> Any:
    """Troca `{prompt}` em todas as strings do corpo JSON (já interpretado, então não há escaping a fazer)."""
    if isinstance(node, str):
        return node.replace(PLACEHOLDER, prompt)
    if isinstance(node, list):
        return [fill_template(n, prompt) for n in node]
    if isinstance(node, dict):
        return {k: fill_template(v, prompt) for k, v in node.items()}
    return node


def extract_path(data: Any, path: str) -> Any:
    """Segue um caminho com pontos, ex.: `choices.0.message.content`."""
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise KeyError(path)
    return current


class HttpTarget:
    """Alvo que recebe um POST com JSON e devolve JSON."""

    def __init__(
        self,
        url: str,
        body_template: Any = None,
        response_path: str = "response",
        headers: dict[str, str] | None = None,
        timeout: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.name = url
        self.url = url
        self.body_template = body_template if body_template is not None else {"message": PLACEHOLDER}
        self.response_path = response_path
        self._client = client or httpx.AsyncClient(timeout=timeout, headers=headers or {})

    async def send(self, prompt: str, history: Sequence[Turn] = ()) -> str:
        response = await self._client.post(self.url, json=fill_template(self.body_template, prompt))
        response.raise_for_status()
        if not self.response_path:
            return response.text
        try:
            value = extract_path(response.json(), self.response_path)
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise ValueError(
                f"campo '{self.response_path}' não encontrado na resposta: {response.text[:200]}"
            ) from exc
        return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)

    async def aclose(self) -> None:
        await self._client.aclose()
