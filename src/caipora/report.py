"""Relatórios: resumo, JSON (base para a comparação no CI) e HTML autocontido."""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .compare import Comparison
from .detectors import Detector, mask_text
from .types import Result, Status

STATUS_LABEL = {
    Status.VULNERAVEL: "Vulnerável",
    Status.SEGURO: "Seguro",
    Status.INCONCLUSIVO: "Inconclusivo",
    Status.ERRO: "Erro",
}


@dataclass
class RunInfo:
    target: str
    pack: str
    llm: str | None
    mutators: list[str]
    started_at: datetime


def summarize(results: Iterable[Result]) -> dict:
    results = list(results)
    total = Counter(r.status for r in results)
    by_category: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        by_category[r.attack.category][r.status] += 1
    evaluated = total[Status.VULNERAVEL] + total[Status.SEGURO]
    return {
        "total": len(results),
        "por_status": {s.value: total[s] for s in Status},
        "taxa_vulnerabilidade": round(total[Status.VULNERAVEL] / evaluated, 4) if evaluated else None,
        "por_categoria": {
            cat: {s.value: c[s] for s in Status} for cat, c in sorted(by_category.items())
        },
    }


def _display_response(result: Result, detectors: list[Detector], masked: bool) -> str | None:
    if result.response is None:
        return None
    return mask_text(result.response, detectors) if masked else result.response


def to_json(
    results: list[Result],
    info: RunInfo,
    detectors: list[Detector],
    masked: bool = True,
    comparison: Comparison | None = None,
) -> dict:
    data = {
        "ferramenta": {"nome": "caipora", "versao": __version__},
        "execucao": {
            "alvo": info.target,
            "pacote": info.pack,
            "llm_juiz": info.llm,
            "mutadores": info.mutators,
            "inicio": info.started_at.isoformat(),
            "dados_mascarados": masked,
        },
        "resumo": summarize(results),
        "resultados": [
            {
                "id": r.attack.id,
                "id_base": r.attack.base_id or r.attack.id,
                "mutador": r.attack.mutator,
                "categoria": r.attack.category,
                "severidade": r.attack.severity,
                "status": r.status.value,
                "objetivo": r.attack.objective,
                "prompt": r.attack.prompt,
                "resposta": _display_response(r, detectors, masked),
                "erro": r.error,
                "tempo_ms": r.elapsed_ms,
                "vereditos": [
                    {"juiz": v.judge, "status": v.status.value, "motivo": v.reason, "evidencias": list(v.evidence)}
                    for v in r.verdicts
                ],
            }
            for r in results
        ],
    }
    if comparison is not None:
        data["comparacao"] = comparison.to_dict()
    return data


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _pct(rate: float | None) -> str:
    return f"{rate * 100:.0f}%" if rate is not None else "—"


def _delta(delta: float | None) -> str:
    if delta is None:
        return ""
    points = delta * 100
    if abs(points) < 0.5:
        return " (sem variação)"
    return f" ({'+' if points > 0 else '−'}{abs(points):.0f} p.p.)"


def to_markdown(data: dict, comparison: Comparison | None = None, max_items: int = 20) -> str:
    """Resumo para o GitHub (step summary ou comentário de PR). Não inclui respostas, só ids e motivos."""
    summary = data["resumo"]
    counts = summary["por_status"]
    exec_ = data.get("execucao", {})
    lines = ["## Caipora · red team", ""]
    lines.append(
        f"Alvo `{exec_.get('alvo')}` · pacote **{exec_.get('pacote')}** · juiz {exec_.get('llm_juiz') or 'heurística de recusa'}"
    )
    lines.append("")
    rate = _pct(summary["taxa_vulnerabilidade"])
    if comparison is not None:
        rate += _delta(comparison.rate_delta)
    lines.append(f"**Taxa de vulnerabilidade: {rate}** · {summary['total']} ataques")
    lines.append("")
    lines.append("| " + " | ".join(STATUS_LABEL[s] for s in Status) + " |")
    lines.append("|" + "---:|" * len(Status))
    lines.append("| " + " | ".join(str(counts[s.value]) for s in Status) + " |")
    lines.append("")

    def esc(text: str) -> str:
        return text.replace("|", "\\|").replace("\n", " ")

    if comparison is not None:
        if comparison.regressions:
            lines.append(f"### ❌ {len(comparison.regressions)} regressão(ões) em relação à base")
            lines.append("")
            lines.append("| Ataque | Categoria | Severidade | Antes | Motivo |")
            lines.append("|---|---|---|---|---|")
            for c in comparison.regressions[:max_items]:
                lines.append(f"| `{c.id}` | {c.category} | {c.severity} | {c.before} | {esc(c.reason)} |")
            if len(comparison.regressions) > max_items:
                lines.append(f"\n…e mais {len(comparison.regressions) - max_items}.")
            lines.append("")
        else:
            lines.append("### ✅ Nenhuma regressão em relação à base")
            lines.append("")
        if comparison.fixes:
            fixed = ", ".join(f"`{c.id}`" for c in comparison.fixes[:max_items])
            lines.append(f"**Corrigidos ({len(comparison.fixes)}):** {fixed}")
            lines.append("")
        if comparison.new_vulnerable:
            lines.append(f"**Ataques novos já vulneráveis:** {', '.join(f'`{i}`' for i in comparison.new_vulnerable[:max_items])}")
            lines.append("")
        for warning in comparison.warnings:
            lines.append(f"> ⚠️ {warning}")
        if comparison.warnings:
            lines.append("")

    vulnerable = [r for r in data["resultados"] if r["status"] == Status.VULNERAVEL.value]
    if vulnerable:
        lines.append(f"<details><summary>Todos os vulneráveis ({len(vulnerable)})</summary>")
        lines.append("")
        for r in vulnerable[:50]:
            reason = next((v["motivo"] for v in r["vereditos"] if v["status"] == Status.VULNERAVEL.value), "")
            lines.append(f"- `{r['id']}` ({r['categoria']}, {r['severidade']}): {esc(reason)}")
        lines.append("")
        lines.append("</details>")
    return "\n".join(lines) + "\n"


def _comparison_html(c: Comparison) -> str:
    e = html.escape
    parts = [f"<h2>Comparação com a base</h2><p>Taxa: {_pct(c.rate_before)} → <b>{_pct(c.rate_after)}</b>{e(_delta(c.rate_delta))}</p>"]
    for w in c.warnings:
        parts.append(f'<p class="warn">⚠️ {e(w)}</p>')
    if c.regressions:
        rows = "".join(
            f"<tr><td><code>{e(x.id)}</code></td><td>{e(x.category)}</td><td>{e(x.severity)}</td><td>{e(x.before)}</td><td>{e(x.reason)}</td></tr>"
            for x in c.regressions
        )
        parts.append(
            f'<h3>{_badge(Status.VULNERAVEL)} {len(c.regressions)} regressão(ões)</h3>'
            f"<table><thead><tr><th>Ataque</th><th>Categoria</th><th>Severidade</th><th>Antes</th><th>Motivo</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        parts.append(f"<p>{_badge(Status.SEGURO)} Nenhuma regressão.</p>")
    if c.fixes:
        parts.append(f"<p><b>Corrigidos ({len(c.fixes)}):</b> {e(', '.join(x.id for x in c.fixes))}</p>")
    if c.new_vulnerable:
        parts.append(f"<p><b>Ataques novos já vulneráveis:</b> {e(', '.join(c.new_vulnerable))}</p>")
    return "".join(parts)


_CSS = """
:root{--bg:#f7f6f3;--card:#fff;--fg:#1d1d1b;--muted:#6b6a66;--line:#e3e1dc;
--vuln:#b42318;--vuln-bg:#fde8e6;--ok:#1a7f4b;--ok-bg:#e3f4ea;--inc:#8a6100;--inc-bg:#fdf3d7;--err:#5b5b5b;--err-bg:#ececec}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--fg:#ecebe7;--muted:#a3a29d;--line:#33322f;
--vuln:#ff8a7a;--vuln-bg:#3b1b17;--ok:#6fd49c;--ok-bg:#13301f;--inc:#f2c55c;--inc-bg:#352a0e;--err:#bbb;--err-bg:#2a2a2a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}h1{margin:0 0 4px;font-size:26px}
.meta{color:var(--muted);font-size:13px;margin-bottom:24px}.meta code{font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:28px;line-height:1.1}.card span{color:var(--muted);font-size:13px}
h2{font-size:18px;margin:28px 0 12px}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}th{color:var(--muted);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.vulneravel{color:var(--vuln);background:var(--vuln-bg)}.seguro{color:var(--ok);background:var(--ok-bg)}
.inconclusivo{color:var(--inc);background:var(--inc-bg)}.erro{color:var(--err);background:var(--err-bg)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}.filters button{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:99px;padding:4px 12px;cursor:pointer;font:inherit;font-size:13px}
.filters button[aria-pressed=true]{border-color:var(--fg)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:8px}
summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
summary .id{font-family:ui-monospace,monospace;font-size:13px}summary .cat{color:var(--muted);font-size:13px}
.body{padding:0 14px 14px}.body h4{margin:12px 0 4px;font-size:13px;color:var(--muted)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;margin:0;font-size:13px}
ul.v{margin:0;padding-left:18px}ul.v li{margin:2px 0}
h3{font-size:15px;margin:16px 0 8px}.warn{color:var(--inc)}
"""

_JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.filters button').forEach(x=>x.setAttribute('aria-pressed',x===b));
const f=b.dataset.f;document.querySelectorAll('details[data-s]').forEach(d=>{d.hidden=f!=='todos'&&d.dataset.s!==f});}));
"""


def _badge(status: Status) -> str:
    return f'<span class="badge {status.value}">{STATUS_LABEL[status]}</span>'


def to_html(
    results: list[Result],
    info: RunInfo,
    detectors: list[Detector],
    masked: bool = True,
    comparison: Comparison | None = None,
) -> str:
    e = html.escape
    summary = summarize(results)
    counts = summary["por_status"]
    rate = summary["taxa_vulnerabilidade"]
    rate_txt = f"{rate * 100:.0f}%" if rate is not None else "—"

    cards = [f'<div class="card"><b>{summary["total"]}</b><span>ataques</span></div>',
             f'<div class="card"><b>{rate_txt}</b><span>taxa de vulnerabilidade</span></div>']
    for s in Status:
        cards.append(f'<div class="card"><b>{counts[s.value]}</b>{_badge(s)}</div>')

    cat_rows = []
    for cat, c in summary["por_categoria"].items():
        cells = "".join(f'<td class="n">{c[s.value]}</td>' for s in Status)
        cat_rows.append(f"<tr><td>{e(cat)}</td>{cells}</tr>")
    cat_head = "".join(f'<th class="n">{STATUS_LABEL[s]}</th>' for s in Status)

    order = {Status.VULNERAVEL: 0, Status.ERRO: 1, Status.INCONCLUSIVO: 2, Status.SEGURO: 3}
    items = []
    for r in sorted(results, key=lambda r: (order[r.status], r.attack.category, r.attack.id)):
        response = _display_response(r, detectors, masked)
        verdicts = "".join(
            f"<li>{_badge(v.status)} <b>{e(v.judge)}</b>: {e(v.reason)}"
            + (f"<br><small>{e('; '.join(v.evidence))}</small>" if v.evidence else "")
            + "</li>"
            for v in r.verdicts
        )
        body = [
            f"<h4>Objetivo</h4><div>{e(r.attack.objective)}</div>",
            f"<h4>Ataque</h4><pre>{e(r.attack.prompt)}</pre>",
        ]
        if r.error:
            body.append(f"<h4>Erro</h4><pre>{e(r.error)}</pre>")
        else:
            body.append(f"<h4>Resposta</h4><pre>{e(response or '')}</pre>")
            body.append(f'<h4>Vereditos</h4><ul class="v">{verdicts}</ul>')
        items.append(
            f'<details data-s="{r.status.value}"><summary>{_badge(r.status)}'
            f'<span class="id">{e(r.attack.id)}</span><span class="cat">{e(r.attack.category)} · '
            f'severidade {e(r.attack.severity)} · {r.elapsed_ms} ms</span></summary>'
            f'<div class="body">{"".join(body)}</div></details>'
        )

    filters = '<button data-f="todos" aria-pressed="true">Todos</button>' + "".join(
        f'<button data-f="{s.value}" aria-pressed="false">{STATUS_LABEL[s]}</button>' for s in Status
    )
    llm = e(info.llm) if info.llm else "nenhum (heurística de recusa)"
    mutators = e(", ".join(info.mutators)) if info.mutators else "nenhum"
    mask_note = "dados pessoais mascarados" if masked else "dados pessoais SEM máscara"

    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório Caipora</title><style>{_CSS}</style></head>
<body><main>
<h1>Relatório Caipora</h1>
<div class="meta">Alvo <code>{e(info.target)}</code> · pacote <b>{e(info.pack)}</b> · juiz {llm} · mutadores {mutators}<br>
{e(info.started_at.astimezone().strftime('%d/%m/%Y %H:%M'))} · caipora {__version__} · {mask_note}</div>
<div class="cards">{"".join(cards)}</div>
{_comparison_html(comparison) if comparison is not None else ""}
<h2>Por categoria</h2>
<table><thead><tr><th>Categoria</th>{cat_head}</tr></thead><tbody>{"".join(cat_rows)}</tbody></table>
<h2>Resultados</h2>
<div class="filters">{filters}</div>
{"".join(items)}
</main><script>{_JS}</script></body></html>
"""


def write_html(
    path: Path,
    results: list[Result],
    info: RunInfo,
    detectors: list[Detector],
    masked: bool,
    comparison: Comparison | None = None,
) -> None:
    path.write_text(to_html(results, info, detectors, masked, comparison), encoding="utf-8")


def now() -> datetime:
    return datetime.now(timezone.utc)
