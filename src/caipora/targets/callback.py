from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .base import Turn


def load_callable(spec: str) -> Callable[..., Any]:
    """Carrega `pacote.modulo:funcao` ou `caminho/arquivo.py:funcao`."""
    module_part, sep, func_name = spec.rpartition(":")
    if not sep or not module_part or not func_name:
        raise ValueError(f"alvo inválido '{spec}': use 'modulo:funcao', 'arquivo.py:funcao' ou uma URL http(s)")
    if module_part.endswith(".py"):
        path = Path(module_part).resolve()
        if not path.is_file():
            raise ValueError(f"arquivo não encontrado: {path}")
        module_spec = importlib.util.spec_from_file_location(path.stem, path)
        if module_spec is None or module_spec.loader is None:
            raise ValueError(f"não foi possível carregar {path}")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
    else:
        module = importlib.import_module(module_part)
    try:
        func = getattr(module, func_name)
    except AttributeError as exc:
        raise ValueError(f"'{func_name}' não existe em {module_part}") from exc
    if not callable(func):
        raise ValueError(f"'{spec}' não é uma função")
    return func


class CallbackTarget:
    """Alvo que é uma função Python `f(prompt) -> str`, síncrona ou assíncrona."""

    def __init__(self, spec: str | Callable[..., Any]) -> None:
        if callable(spec):
            self._func = spec
            self.name = getattr(spec, "__qualname__", repr(spec))
        else:
            self._func = load_callable(spec)
            self.name = spec

    def accepts_tools(self) -> bool:
        try:
            params = inspect.signature(self._func).parameters.values()
        except (TypeError, ValueError):
            return False
        positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL)]
        return len(positional) >= 2 or any(p.kind is p.VAR_POSITIONAL for p in positional)

    async def send(self, prompt: str, history: Sequence[Turn] = (), tools: Any = None) -> str:
        args: tuple = (prompt,)
        if tools is not None:
            if not self.accepts_tools():
                raise ValueError(f"'{self.name}' precisa aceitar (prompt, ferramentas) para rodar no honeypot")
            args = (prompt, tools)
        if inspect.iscoroutinefunction(self._func):
            result = await self._func(*args)
        else:
            # Roda em thread para uma função lenta não travar as outras requisições.
            result = await asyncio.to_thread(self._func, *args)
        return str(result)

    async def aclose(self) -> None:
        return None
