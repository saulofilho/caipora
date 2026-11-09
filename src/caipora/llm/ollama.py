from __future__ import annotations

import os

import httpx


class OllamaLLM:
    """Modelo local via Ollama. Usa OLLAMA_HOST se definido."""

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        timeout: float = 180.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.model = model
        self.name = f"ollama/{model}"
        url = base_url or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        self.base_url = url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def complete(self, system: str, user: str, json_mode: bool = False) -> str:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0},
        }
        if json_mode:
            payload["format"] = "json"
        response = await self._client.post(f"{self.base_url}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()["message"]["content"]

    async def aclose(self) -> None:
        await self._client.aclose()
