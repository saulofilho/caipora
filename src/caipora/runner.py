"""Executa os ataques contra o alvo e aplica os juízes."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable

from .detectors import Detector
from .honeypot import Environment
from .judges import DetectorJudge, Judge, LLMJudge, RefusalHeuristicJudge, ToolCallJudge
from .llm import LLM
from .targets import Target
from .types import Attack, Result, Status, ToolCall, Verdict


class Runner:
    def __init__(
        self,
        target: Target,
        detectors: Iterable[Detector],
        llm: LLM | None = None,
        concurrency: int = 4,
        timeout: float = 60.0,
        on_result: Callable[[Result], None] | None = None,
        environment: Environment | None = None,
    ) -> None:
        detectors = list(detectors)
        self.target = target
        self.environment = environment
        # Ambiente com log compartilhado não sabe separar chamadas de ataques simultâneos.
        self.concurrency = 1 if environment is not None and environment.exclusive else max(1, concurrency)
        self.timeout = timeout
        self.on_result = on_result
        self._judges: dict[str, Judge] = {
            "detectores": DetectorJudge(detectors),
            "llm": LLMJudge(llm) if llm else RefusalHeuristicJudge(),
            "ferramentas": ToolCallJudge(detectors),
        }

    async def run(self, attacks: list[Attack]) -> list[Result]:
        if self.environment is None and any("ferramentas" in a.judges for a in attacks):
            raise ValueError("este pacote testa agentes e precisa de um ambiente: use --ambiente honeypot (ou honeypot-mcp:ARQUIVO)")
        semaphore = asyncio.Semaphore(self.concurrency)

        async def one(attack: Attack) -> Result:
            async with semaphore:
                result = await self.run_one(attack)
            if self.on_result:
                self.on_result(result)
            return result

        return list(await asyncio.gather(*(one(a) for a in attacks)))

    async def run_one(self, attack: Attack) -> Result:
        start = time.perf_counter()
        session = self.environment.start() if self.environment else None
        calls: list[ToolCall] = []
        try:
            tools = session.toolbox if session else None
            response = await asyncio.wait_for(self.target.send(attack.prompt, tools=tools), self.timeout)
        except Exception as exc:  # qualquer falha do alvo vira resultado "erro", não derruba a execução
            message = str(exc) or ("tempo esgotado" if isinstance(exc, TimeoutError) else "")
            calls = session.finish() if session else []
            return Result(attack, None, error=f"{type(exc).__name__}: {message}", elapsed_ms=_ms(start), tool_calls=calls)
        if session:
            calls = session.finish()

        verdicts: list[Verdict] = []
        for judge_name in attack.judges:
            judge = self._judges[judge_name]
            try:
                verdicts.append(await judge.evaluate(attack, response, calls))
            except Exception as exc:
                verdicts.append(Verdict(judge.name, Status.INCONCLUSIVO, f"falha no juiz: {type(exc).__name__}: {exc}"))
        return Result(attack, response, verdicts, elapsed_ms=_ms(start), tool_calls=calls)


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
