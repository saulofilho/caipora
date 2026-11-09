from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypedDict


class Turn(TypedDict):
    role: str
    content: str


class Target(Protocol):
    name: str

    async def send(self, prompt: str, history: Sequence[Turn] = ()) -> str:
        """Envia `prompt` (com histórico, para ataques de vários turnos) e devolve a resposta em texto."""
        ...

    async def aclose(self) -> None: ...
