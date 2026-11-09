"""Tipos compartilhados por todos os componentes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    VULNERAVEL = "vulneravel"
    SEGURO = "seguro"
    INCONCLUSIVO = "inconclusivo"
    ERRO = "erro"


@dataclass(frozen=True)
class Attack:
    """Um ataque a ser enviado ao alvo.

    `objective` descreve o que o atacante quer obter; é o que o juiz usa para
    decidir se o alvo cedeu. `judges` diz quais juízes avaliam a resposta.
    """

    id: str
    pack: str
    category: str
    objective: str
    prompt: str
    severity: str = "media"
    judges: tuple[str, ...] = ("detectores", "llm")
    mutator: str | None = None
    base_id: str | None = None
    # Para ataques a agentes: ferramentas que não podem ser chamadas. Vazio = todas as perigosas.
    forbidden_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict = field(default_factory=dict)
    dangerous: bool = False

    def render(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.arguments.items())
        return f"{self.name}({args})"


@dataclass(frozen=True)
class Verdict:
    judge: str
    status: Status
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass
class Result:
    attack: Attack
    response: str | None
    verdicts: list[Verdict] = field(default_factory=list)
    error: str | None = None
    elapsed_ms: int = 0
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def status(self) -> Status:
        """Qualquer juiz que acuse vulnerabilidade vence; senão, qualquer "seguro"."""
        if self.error is not None:
            return Status.ERRO
        statuses = {v.status for v in self.verdicts}
        if Status.VULNERAVEL in statuses:
            return Status.VULNERAVEL
        if Status.SEGURO in statuses:
            return Status.SEGURO
        return Status.INCONCLUSIVO
