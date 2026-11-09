"""Auditoria de servidores MCP.

Estática: lê as definições das ferramentas (nome, descrição, schema,
anotações) e procura envenenamento, capacidades perigosas e parâmetros
livres demais. Dinâmica (opcional): chama ferramentas que o usuário indicar
e procura instruções escondidas na saída.

A auditoria estática nunca executa ferramenta nenhuma.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from . import __version__
from .mcp import McpTool, tool_result_text

SEVERITIES = ("alta", "media", "baixa")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    tool: str
    message: str
    evidence: str = ""


_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")

_INSTRUCTIONS = [
    (r"<\s*(important|system|instructions?|importante|secret)\s*>", "tag de instrução escondida"),
    (r"\bignore\s+(all|any|the|previous|prior)\b|\bignor[ea]\s+(as|todas|qualquer)\b", "manda ignorar instruções"),
    (r"(do\s*n[o']t|never)\s+(tell|mention|inform|reveal|notify)\b.{0,20}\buser", "manda esconder algo do usuário"),
    (r"n[ãa]o\s+(conte|diga|mencione|avise|informe|revele)\b.{0,25}\busu[áa]rio", "manda esconder algo do usuário"),
    (r"\bbefore\s+(using|calling|running)\b|\bantes\s+de\s+(usar|chamar|executar|responder)\b", "impõe passo prévio ao modelo"),
    (r"\b(you|the\s+assistant|the\s+model)\s+(must|should|need\s+to)\b|\bvoc[êe]\s+(deve|precisa)\b", "dá ordens ao modelo"),
    (r"~/\.ssh|\bid_rsa\b|\.env\b|mcp\.json|\.aws/credentials|/etc/passwd|\bcredentials?\b", "menciona arquivo de credenciais"),
    (r"\b(send|forward|upload|post)\b.{0,40}\b(to|para)\b.{0,40}(https?://|@)|\benvi(e|a|ar)\b.{0,40}\bpara\b.{0,40}(https?://|@)", "manda enviar dados para fora"),
]
_INSTRUCTIONS_RE = [(re.compile(p, re.IGNORECASE | re.DOTALL), label) for p, label in _INSTRUCTIONS]

_CAPABILITIES = [
    ("alta", r"exec|shell|command|comando|run_?(cmd|script|code)|eval|terminal|subprocess|bash", "executa comandos ou código"),
    ("media", r"delet|drop|remov|destroy|truncate|wipe|apag|exclu|limpar|clear", "apaga dados"),
    ("media", r"write_?file|save_?file|upload|escrever|gravar|salvar_?arquivo|put_?object", "escreve arquivos"),
    ("media", r"fetch|http|request|url|download|browse|navegar|baixar", "faz requisições de rede (risco de SSRF/exfiltração)"),
    ("media", r"send|email|e-mail|mensagem|message|transfer|pay|pagamento|pix|enviar|transferir", "age em nome do usuário (envio, pagamento)"),
    ("media", r"permission|role|grant|sudo|admin|permiss|papel", "altera permissões"),
    ("baixa", r"read_?file|ler_?arquivo|cat\b|open_?file|query|sql|consulta", "lê arquivos ou banco"),
]
_CAPABILITIES_RE = [(sev, re.compile(p, re.IGNORECASE), label) for sev, p, label in _CAPABILITIES]

_RISKY_PARAMS = re.compile(r"^(cmd|command|comando|script|code|codigo|código|sql|path|caminho|file|arquivo|url|uri|endpoint|host)s?$", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s\"'<>)]+")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_DESTRUCTIVE_NAME = re.compile(_CAPABILITIES[0][1] + "|" + _CAPABILITIES[1][1], re.IGNORECASE)


def _schema_texts(schema: dict) -> list[str]:
    """Descrições dentro do schema também chegam ao modelo, então também são analisadas."""
    out = []
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in ("description", "title") and isinstance(value, str):
                out.append(value)
            elif isinstance(value, dict):
                out.extend(_schema_texts(value))
            elif isinstance(value, list):
                for v in value:
                    out.extend(_schema_texts(v) if isinstance(v, dict) else [])
    return out


def _snippet(text: str, match: re.Match, width: int = 50) -> str:
    start, end = max(0, match.start() - width), min(len(text), match.end() + width)
    return ("…" if start else "") + text[start:end].replace("\n", " ") + ("…" if end < len(text) else "")


def scan_text(text: str, tool: str, where: str) -> list[Finding]:
    """Procura sinais de instrução escondida num texto que o modelo vai ler."""
    findings = []
    invisible = _INVISIBLE.findall(text)
    if invisible:
        names = sorted({unicodedata.name(c, f"U+{ord(c):04X}") for c in invisible})
        findings.append(Finding("alta", "invisivel", tool, f"{where} tem {len(invisible)} caractere(s) invisível(is)", ", ".join(names[:5])))
    visible = _INVISIBLE.sub("", text)
    for pattern, label in _INSTRUCTIONS_RE:
        if m := pattern.search(visible):
            findings.append(Finding("alta", "envenenamento", tool, f"{where}: {label}", _snippet(visible, m)))
    if m := _BASE64_BLOB.search(visible):
        findings.append(Finding("media", "texto_codificado", tool, f"{where} tem um bloco que parece codificado (base64)", _snippet(visible, m, 10)))
    return findings


def audit_tools(tools: list[McpTool]) -> list[Finding]:
    findings: list[Finding] = []
    names = [t.name for t in tools]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        findings.append(Finding("alta", "nome_duplicado", dup, "mais de uma ferramenta com o mesmo nome"))

    for tool in tools:
        name = tool.name
        texts = [("descrição", tool.description)] + [("schema", t) for t in _schema_texts(tool.input_schema)]
        for where, text in texts:
            findings.extend(scan_text(text, name, where))
            for url in _URL.findall(text):
                findings.append(Finding("media", "url", name, f"{where} contém uma URL", url))

        if _INVISIBLE.search(name):
            findings.append(Finding("alta", "invisivel", name, "o nome tem caracteres invisíveis"))
        if not tool.description.strip():
            findings.append(Finding("baixa", "sem_descricao", name, "ferramenta sem descrição"))
        elif len(tool.description) > 1000:
            findings.append(Finding("baixa", "descricao_longa", name, f"descrição com {len(tool.description)} caracteres (espaço para esconder instruções)"))

        others = [n for n in names if n != name and len(n) > 3]
        mentioned = [n for n in others if re.search(rf"\b{re.escape(n)}\b", tool.description)]
        if mentioned:
            findings.append(Finding("media", "referencia_cruzada", name, "a descrição fala de outra(s) ferramenta(s), possível sombreamento", ", ".join(mentioned)))

        haystack = f"{name} {tool.description}"
        for sev, pattern, label in _CAPABILITIES_RE:
            if pattern.search(haystack):
                findings.append(Finding(sev, "capacidade", name, f"capacidade sensível: {label}"))
                break

        ann = tool.annotations or {}
        if ann.get("readOnlyHint") is True and _DESTRUCTIVE_NAME.search(haystack):
            findings.append(Finding("alta", "anotacao_enganosa", name, "anotada como somente leitura, mas o nome/descrição sugere ação destrutiva"))

        schema = tool.input_schema or {}
        if schema and schema.get("type") not in (None, "object"):
            findings.append(Finding("baixa", "schema", name, f"inputSchema com type '{schema.get('type')}' (esperado 'object')"))
        for param, spec in (schema.get("properties") or {}).items():
            if not isinstance(spec, dict) or not _RISKY_PARAMS.match(param):
                continue
            if spec.get("type", "string") == "string" and not any(k in spec for k in ("enum", "pattern", "const", "format")):
                findings.append(Finding("media", "parametro_livre", name, f"parâmetro '{param}' aceita texto livre, sem enum/pattern"))

    findings.sort(key=lambda f: (_RANK[f.severity], f.tool, f.code))
    return findings


def audit_output(tool: str, result: dict) -> list[Finding]:
    """Saída de uma ferramenta também vai para o modelo: mesma análise da descrição."""
    return scan_text(tool_result_text(result), tool, "saída da chamada")


def count(findings: Iterable[Finding]) -> dict[str, int]:
    findings = list(findings)
    return {s: sum(f.severity == s for f in findings) for s in SEVERITIES}


def should_fail(findings: list[Finding], threshold: str | None) -> bool:
    if not threshold:
        return False
    return any(_RANK[f.severity] <= _RANK[threshold] for f in findings)


def to_json(target: str, server_info: dict, tools: list[McpTool], findings: list[Finding]) -> dict:
    return {
        "ferramenta": {"nome": "caipora", "versao": __version__},
        "servidor": {"alvo": target, "info": server_info, "ferramentas": [t.name for t in tools]},
        "resumo": count(findings),
        "achados": [
            {"severidade": f.severity, "codigo": f.code, "ferramenta": f.tool, "mensagem": f.message, "evidencia": f.evidence}
            for f in findings
        ],
    }


def to_markdown(data: dict) -> str:
    resumo = data["resumo"]
    lines = [
        "## Caipora · auditoria MCP",
        "",
        f"Servidor `{data['servidor']['alvo']}` · {len(data['servidor']['ferramentas'])} ferramentas",
        "",
        f"**Alta: {resumo['alta']} · Média: {resumo['media']} · Baixa: {resumo['baixa']}**",
        "",
    ]
    if data["achados"]:
        lines += ["| Severidade | Ferramenta | Achado | Evidência |", "|---|---|---|---|"]
        for a in data["achados"]:
            ev = a["evidencia"].replace("|", "\\|").replace("\n", " ")[:120]
            lines.append(f"| {a['severidade']} | `{a['ferramenta']}` | {a['mensagem']} | {ev} |")
    else:
        lines.append("Nenhum achado.")
    return "\n".join(lines) + "\n"


def to_html(data: dict) -> str:
    from .report import _CSS

    e = html.escape
    resumo = data["resumo"]
    cls = {"alta": "vulneravel", "media": "inconclusivo", "baixa": "erro"}
    rows = "".join(
        f'<tr><td><span class="badge {cls[a["severidade"]]}">{e(a["severidade"])}</span></td>'
        f'<td><code>{e(a["ferramenta"])}</code></td><td>{e(a["mensagem"])}</td><td><small>{e(a["evidencia"])}</small></td></tr>'
        for a in data["achados"]
    )
    cards = "".join(
        f'<div class="card"><b>{resumo[s]}</b><span class="badge {cls[s]}">{s}</span></div>' for s in SEVERITIES
    )
    tools = ", ".join(e(t) for t in data["servidor"]["ferramentas"]) or "nenhuma"
    table = (
        f"<table><thead><tr><th>Severidade</th><th>Ferramenta</th><th>Achado</th><th>Evidência</th></tr></thead><tbody>{rows}</tbody></table>"
        if rows
        else "<p>Nenhum achado.</p>"
    )
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditoria MCP Caipora</title><style>{_CSS}</style></head>
<body><main>
<h1>Auditoria MCP</h1>
<div class="meta">Servidor <code>{e(data['servidor']['alvo'])}</code> · {e(json.dumps(data['servidor']['info'], ensure_ascii=False))} · caipora {__version__}<br>Ferramentas: {tools}</div>
<div class="cards">{cards}</div>
<h2>Achados</h2>{table}
</main></body></html>
"""

