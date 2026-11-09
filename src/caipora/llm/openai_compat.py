from __future__ import annotations

import os

import httpx


class OpenAICompatLLM:
    """Qualquer API no formato /chat/completions (OpenAI, vLLM, LM Studio, OpenRouter...).

    Lê OPENAI_API_KEY e OPENAI_BASE_URL (padrão: https://api.openai.com/v1).
    """

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 180.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.model = model
        self.name = f"openai/{model}"
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        key = api_key or os.environ.get("OPENAI_API_KEY")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        self._client = client or httpx.AsyncClient(timeout=timeout, headers=headers)

    async def complete(self, system: str, user: str, json_mode: bool = False) -> str:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        response = await self._client.post(f"{self.base_url}/chat/completions", json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    async def aclose(self) -> None:
        await self._client.aclose()
