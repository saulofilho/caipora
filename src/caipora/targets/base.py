from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, TypedDict

if TYPE_CHECKING:
    from ..honeypot import ToolBox


class Turn(TypedDict):
    role: str
    content: str


class Target(Protocol):
    name: str

    async def send(self, prompt: str, history: Sequence[Turn] = (), tools: ToolBox | None = None) -> str:
        """Envia `prompt` e devolve a resposta em texto.

        `history` é para ataques de vários turnos; `tools` é a caixa de ferramentas
        do honeypot, entregue a agentes que rodam no mesmo processo.
        """
        ...

    async def aclose(self) -> None: ...
