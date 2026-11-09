"""Detectores de dados pessoais brasileiros.

Usam regex + validação de dígito verificador sempre que existe uma. Isso é
mais barato e mais confiável que perguntar a um LLM "tem CPF aqui?".
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Match:
    kind: str
    value: str

    @property
    def key(self) -> str:
        """Forma normalizada, para comparar o mesmo dado escrito de jeitos diferentes."""
        if self.kind == "email":
            return f"{self.kind}:{self.value.lower()}"
        digits = re.sub(r"\D", "", self.value)
        return f"{self.kind}:{digits or self.value.lower()}"


class Detector(Protocol):
    kind: str
    label: str

    def find(self, text: str) -> list[Match]: ...


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def cpf_valido(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        total = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (total * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def cnpj_valido(value: str) -> bool:
    d = _digits(value)
    if len(d) != 14 or d == d[0] * 14:
        return False
    weights = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for n in (12, 13):
        w = weights if n == 12 else [6, *weights]
        rest = sum(int(d[i]) * w[i] for i in range(n)) % 11
        if (0 if rest < 2 else 11 - rest) != int(d[n]):
            return False
    return True


def cnh_valida(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or d == d[0] * 11:
        return False
    dv1 = sum(int(d[i]) * (9 - i) for i in range(9)) % 11
    discount = 0
    if dv1 >= 10:
        dv1, discount = 0, 2
    rest = sum(int(d[i]) * (i + 1) for i in range(9)) % 11
    dv2 = 0 if rest >= 10 else rest - discount
    return f"{dv1}{dv2}" == d[-2:]


def luhn_valido(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19 or d == d[0] * len(d):
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def telefone_formatado(value: str) -> bool:
    # Exige alguma formatação para não confundir com CPF sem pontuação.
    return any(c in value for c in "()+ -")


class RegexDetector:
    def __init__(
        self,
        kind: str,
        label: str,
        pattern: str,
        validator: Callable[[str], bool] | None = None,
        context: str | None = None,
        context_window: int = 40,
        flags: int = 0,
    ) -> None:
        self.kind = kind
        self.label = label
        self._pattern = re.compile(pattern, flags)
        self._validator = validator
        self._context = re.compile(context, re.IGNORECASE) if context else None
        self._window = context_window

    def find(self, text: str) -> list[Match]:
        found: list[Match] = []
        for m in self._pattern.finditer(text):
            value = m.group(0).strip(" -.")
            if self._validator and not self._validator(value):
                continue
            if self._context:
                before = text[max(0, m.start() - self._window) : m.start()]
                if not self._context.search(before):
                    continue
            found.append(Match(self.kind, value))
        return found


BR_DETECTORS: list[Detector] = [
    RegexDetector("cpf", "CPF", r"(?<![\d.])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?![\d-])", cpf_valido),
    RegexDetector("cnpj", "CNPJ", r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)", cnpj_valido),
    RegexDetector(
        "cnh", "CNH", r"(?<!\d)\d{11}(?!\d)", cnh_valida, context=r"cnh|habilita|registro", context_window=60
    ),
    RegexDetector("cartao", "Cartão de crédito", r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", luhn_valido),
    RegexDetector(
        "telefone",
        "Telefone celular",
        r"(?<!\d)(?:\+55\s?)?\(?[1-9]{2}\)?\s?9\d{4}[-\s]?\d{4}(?!\d)",
        telefone_formatado,
    ),
    RegexDetector("email", "E-mail", r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    RegexDetector(
        "pix_aleatoria",
        "Chave Pix aleatória",
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        context=r"pix|chave",
        context_window=60,
        flags=re.IGNORECASE,
    ),
    RegexDetector("cep", "CEP", r"(?<!\d)\d{5}-\d{3}(?!\d)", context=r"cep|endere|rua|av\.|avenida"),
]

DETECTOR_SETS: dict[str, list[Detector]] = {"br": BR_DETECTORS}


def find_all(text: str, detectors: Iterable[Detector]) -> list[Match]:
    seen: set[str] = set()
    out: list[Match] = []
    for detector in detectors:
        for match in detector.find(text):
            if match.key not in seen:
                seen.add(match.key)
                out.append(match)
    return out


def mask(value: str) -> str:
    """Mascara um dado para o relatório: mantém os 3 primeiros e 2 últimos dígitos."""
    if "@" in value:
        user, _, domain = value.partition("@")
        return f"{user[:1]}***@{domain}"
    total = sum(c.isdigit() for c in value)
    seen = 0
    out = []
    for c in value:
        if c.isdigit():
            seen += 1
            out.append(c if seen <= 3 or seen > total - 2 else "*")
        elif c.isalnum():
            out.append("*")
        else:
            out.append(c)
    return "".join(out)


def mask_text(text: str, detectors: Iterable[Detector]) -> str:
    for match in find_all(text, detectors):
        text = text.replace(match.value, mask(match.value))
    return text
