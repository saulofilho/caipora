from __future__ import annotations

from typing import Protocol


class LLM(Protocol):
    name: str

    async def complete(self, system: str, user: str, json_mode: bool = False) -> str: ...

    async def aclose(self) -> None: ...
