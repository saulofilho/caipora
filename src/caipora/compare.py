"""Comparação entre duas execuções (formato JSON do relatório).

Serve ao modo CI: rodar na branch principal, guardar o JSON e, em cada PR,
dizer o que piorou e o que melhorou.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

VULN = "vulneravel"


@dataclass(frozen=True)
class Change:
    id: str
    category: str
    severity: str
    before: str
    after: str
    reason: str = ""


@dataclass
class Comparison:
    regressions: list[Change] = field(default_factory=list)  # passou a ser vulnerável
    fixes: list[Change] = field(default_factory=list)  # deixou de ser vulnerável
    new_vulnerable: list[str] = field(default_factory=list)  # ataque que não existia na base e é vulnerável
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    rate_before: float | None = None
    rate_after: float | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def rate_delta(self) -> float | None:
        if self.rate_before is None or self.rate_after is None:
            return None
        return round(self.rate_after - self.rate_before, 4)

    def to_dict(self) -> dict:
        def change(c: Change) -> dict:
            return {"id": c.id, "categoria": c.category, "severidade": c.severity, "antes": c.before, "depois": c.after, "motivo": c.reason}

        return {
            "regressoes": [change(c) for c in self.regressions],
            "correcoes": [change(c) for c in self.fixes],
            "novos_vulneraveis": self.new_vulnerable,
            "ataques_novos": self.added,
            "ataques_removidos": self.removed,
            "taxa_antes": self.rate_before,
            "taxa_depois": self.rate_after,
            "variacao_taxa": self.rate_delta,
            "avisos": self.warnings,
        }


def load_run(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"arquivo de base não encontrado: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} não é um JSON válido: {exc}") from exc
    if not isinstance(data, dict) or "resultados" not in data:
        raise ValueError(f"{path} não parece um resultado da caipora (falta 'resultados')")
    return data


def _main_reason(item: dict) -> str:
    for v in item.get("vereditos", []):
        if v.get("status") == VULN:
            return v.get("motivo", "")
    return ""


def compare(base: dict, current: dict) -> Comparison:
    before = {r["id"]: r for r in base["resultados"]}
    after = {r["id"]: r for r in current["resultados"]}
    out = Comparison(
        rate_before=base.get("resumo", {}).get("taxa_vulnerabilidade"),
        rate_after=current.get("resumo", {}).get("taxa_vulnerabilidade"),
    )

    base_exec, cur_exec = base.get("execucao", {}), current.get("execucao", {})
    for key, label in (("pacote", "pacote"), ("llm_juiz", "juiz"), ("mutadores", "mutadores")):
        if base_exec.get(key) != cur_exec.get(key):
            out.warnings.append(f"{label} diferente da base ({base_exec.get(key)!r} → {cur_exec.get(key)!r}); a comparação pode ter ruído")

    for id_, now in after.items():
        prev = before.get(id_)
        if prev is None:
            out.added.append(id_)
            if now["status"] == VULN:
                out.new_vulnerable.append(id_)
            continue
        if prev["status"] == now["status"]:
            continue
        # "erro" não conta como correção nem como regressão: não sabemos o resultado.
        if now["status"] == VULN and prev["status"] != "erro":
            out.regressions.append(
                Change(id_, now["categoria"], now["severidade"], prev["status"], now["status"], _main_reason(now))
            )
        elif prev["status"] == VULN and now["status"] != "erro":
            out.fixes.append(Change(id_, now["categoria"], now["severidade"], prev["status"], now["status"]))
    out.removed = sorted(set(before) - set(after))
    return out
