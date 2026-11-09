"""Provedores de LLM usados pelo juiz (e, nas próximas fases, para gerar ataques)."""

from __future__ import annotations

from .base import LLM
from .ollama import OllamaLLM
from .openai_compat import OpenAICompatLLM

__all__ = ["LLM", "OllamaLLM", "OpenAICompatLLM", "build_llm"]


def build_llm(spec: str) -> LLM:
    """`ollama/<modelo>` ou `openai/<modelo>` (qualquer API compatível, via OPENAI_BASE_URL)."""
    provider, sep, model = spec.partition("/")
    if not sep or not model:
        raise ValueError(f"LLM inválido '{spec}': use 'ollama/<modelo>' ou 'openai/<modelo>'")
    if provider == "ollama":
        return OllamaLLM(model)
    if provider == "openai":
        return OpenAICompatLLM(model)
    raise ValueError(f"provedor desconhecido '{provider}': use 'ollama' ou 'openai'")
