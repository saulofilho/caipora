"""Linha de comando: `caipora run` e `caipora pacotes`."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .compare import Comparison, compare, load_run
from .llm import LLM, build_llm
from .mutators import MUTATORS, expand
from .packs import builtin_packs, load_pack
from .report import STATUS_LABEL, RunInfo, now, summarize, to_json, to_markdown, write_html, write_json
from .runner import Runner
from .targets import build_target
from .types import Result, Status

_COLORS = {Status.VULNERAVEL: "31", Status.SEGURO: "32", Status.INCONCLUSIVO: "33", Status.ERRO: "90"}
_ICONS = {Status.VULNERAVEL: "✗", Status.SEGURO: "✓", Status.INCONCLUSIVO: "?", Status.ERRO: "!"}


def _paint(text: str, status: Status) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{_COLORS[status]}m{text}\033[0m"


def _parse_header(raw: str) -> tuple[str, str]:
    name, sep, value = raw.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError(f"cabeçalho inválido '{raw}': use 'Nome: valor'")
    return name.strip(), value.strip()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="caipora", description="Red teaming de LLMs com foco no Brasil e na LGPD.")
    parser.add_argument("--version", action="version", version=f"caipora {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="roda um pacote de ataques contra um alvo")
    run.add_argument("alvo", help="URL http(s), 'modulo:funcao' ou 'arquivo.py:funcao'")
    run.add_argument("-p", "--pacote", default="lgpd", help="nome de um pacote embutido ou caminho de um .toml (padrão: lgpd)")
    run.add_argument("-m", "--mutadores", default="", help=f"lista separada por vírgula, ou 'todos' ({', '.join(MUTATORS)})")
    run.add_argument("-c", "--categorias", default="", help="roda só estas categorias (separadas por vírgula)")
    run.add_argument("--llm", help="LLM juiz: 'ollama/<modelo>' ou 'openai/<modelo>'. Sem ele, usa heurística de recusa")
    run.add_argument("--http-body", help='corpo JSON com {prompt}, ex.: \'{"message": "{prompt}"}\'')
    run.add_argument("--http-resposta", default="response", help="caminho do texto na resposta JSON, ex.: choices.0.message.content (vazio = corpo inteiro)")
    run.add_argument("-H", "--header", action="append", type=_parse_header, default=[], help="cabeçalho HTTP 'Nome: valor' (repetível)")
    run.add_argument("--concorrencia", type=int, default=4, help="requisições simultâneas (padrão: 4)")
    run.add_argument("--timeout", type=float, default=60.0, help="segundos por requisição ao alvo (padrão: 60)")
    run.add_argument("-o", "--saida", type=Path, default=Path("relatorio-caipora.html"), help="arquivo HTML do relatório")
    run.add_argument("--json", type=Path, help="também grava os resultados em JSON")
    run.add_argument("--sem-mascara", action="store_true", help="não mascara dados pessoais no relatório")
    run.add_argument("--markdown", type=Path, help="grava um resumo em Markdown (ex.: $GITHUB_STEP_SUMMARY)")
    run.add_argument("--base", type=Path, help="JSON de uma execução anterior para comparar (ex.: da branch main)")
    _add_ci_flags(run)

    cmp_ = sub.add_parser("comparar", help="compara dois JSONs de resultado")
    cmp_.add_argument("base", type=Path, help="JSON da execução anterior")
    cmp_.add_argument("atual", type=Path, help="JSON da execução nova")
    cmp_.add_argument("--markdown", type=Path, help="grava o resumo em Markdown")
    _add_ci_flags(cmp_, vulneravel=False)

    sub.add_parser("pacotes", help="lista pacotes, categorias e mutadores")
    return parser


def _add_ci_flags(p: argparse.ArgumentParser, vulneravel: bool = True) -> None:
    if vulneravel:
        p.add_argument("--falhar-se-vulneravel", action="store_true", help="sai com código 1 se houver vulnerabilidade")
    p.add_argument("--falhar-se-regressao", action="store_true", help="sai com código 1 se algo passou a ser vulnerável em relação à base")
    p.add_argument("--tolerancia", type=int, default=0, help="regressões aceitas antes de falhar (padrão: 0)")


def _print_comparison(c: Comparison) -> None:
    for w in c.warnings:
        print(_paint(f"aviso: {w}", Status.INCONCLUSIVO))
    if c.regressions:
        print(_paint(f"{len(c.regressions)} regressão(ões) em relação à base:", Status.VULNERAVEL))
        for x in c.regressions:
            print(_paint(f"  ✗ {x.id} ({x.category}, {x.severity}): {x.before} → {x.after}", Status.VULNERAVEL))
    else:
        print(_paint("nenhuma regressão em relação à base", Status.SEGURO))
    if c.fixes:
        print(_paint(f"{len(c.fixes)} corrigido(s): {', '.join(x.id for x in c.fixes)}", Status.SEGURO))
    if c.new_vulnerable:
        print(f"ataques novos já vulneráveis: {', '.join(c.new_vulnerable)}")


def _regression_failed(args: argparse.Namespace, c: Comparison | None) -> bool:
    return bool(args.falhar_se_regressao and c is not None and len(c.regressions) > args.tolerancia)


def _cmd_comparar(args: argparse.Namespace) -> int:
    base, current = load_run(args.base), load_run(args.atual)
    c = compare(base, current)
    _print_comparison(c)
    if args.markdown:
        args.markdown.write_text(to_markdown(current, c), encoding="utf-8")
    return 1 if _regression_failed(args, c) else 0


def _cmd_pacotes() -> int:
    for name in builtin_packs():
        pack = load_pack(name)
        counts = Counter(a.category for a in pack.attacks)
        print(f"{pack.name} ({len(pack.attacks)} ataques)\n  {pack.description}")
        for cat, n in sorted(counts.items()):
            print(f"  - {cat}: {n}")
    print(f"\nmutadores: {', '.join(MUTATORS)}")
    return 0


def _split(raw: str) -> list[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


async def _run(args: argparse.Namespace) -> int:
    base = load_run(args.base) if args.base else None  # falha cedo, antes de gastar tempo com os ataques
    pack = load_pack(args.pacote)
    attacks = pack.attacks
    if args.categorias:
        wanted = set(_split(args.categorias))
        unknown = wanted - set(pack.categories)
        if unknown:
            raise ValueError(f"categorias inexistentes: {', '.join(sorted(unknown))} (há: {', '.join(pack.categories)})")
        attacks = [a for a in attacks if a.category in wanted]
    mutators = list(MUTATORS) if args.mutadores.strip() == "todos" else _split(args.mutadores)
    attacks = expand(attacks, mutators)

    http_options = {}
    if args.alvo.startswith(("http://", "https://")):
        body = json.loads(args.http_body) if args.http_body else None
        http_options = {
            "body_template": body,
            "response_path": args.http_resposta,
            "headers": dict(args.header),
            "timeout": args.timeout,
        }
    target = build_target(args.alvo, **http_options)
    llm: LLM | None = build_llm(args.llm) if args.llm else None

    total = len(attacks)
    done = 0

    def progress(result: Result) -> None:
        nonlocal done
        done += 1
        s = result.status
        line = f"[{done:>3}/{total}] {_ICONS[s]} {result.attack.id:<24} {result.attack.category:<18} {STATUS_LABEL[s]}"
        print(_paint(line, s), flush=True)

    print(f"caipora {__version__} · alvo {target.name} · pacote {pack.name} · {total} ataques · juiz {llm.name if llm else 'heurística'}\n")
    info = RunInfo(target=target.name, pack=pack.name, llm=llm.name if llm else None, mutators=mutators, started_at=now())
    try:
        runner = Runner(target, pack.detectors, llm, concurrency=args.concorrencia, timeout=args.timeout, on_result=progress)
        results = await runner.run(attacks)
    finally:
        await target.aclose()
        if llm:
            await llm.aclose()

    masked = not args.sem_mascara
    data = to_json(results, info, pack.detectors, masked)
    comparison = compare(base, data) if base is not None else None
    if comparison is not None:
        data["comparacao"] = comparison.to_dict()
    write_html(args.saida, results, info, pack.detectors, masked, comparison)
    if args.json:
        write_json(args.json, data)
    if args.markdown:
        args.markdown.write_text(to_markdown(data, comparison), encoding="utf-8")

    summary = summarize(results)
    counts = summary["por_status"]
    rate = summary["taxa_vulnerabilidade"]
    print()
    print("  ".join(_paint(f"{STATUS_LABEL[s]}: {counts[s.value]}", s) for s in Status))
    if rate is not None:
        print(f"taxa de vulnerabilidade: {rate * 100:.0f}% dos ataques avaliados")
    if counts[Status.INCONCLUSIVO.value] and not llm:
        print("dica: use --llm ollama/<modelo> para avaliar os inconclusivos")
    if comparison is not None:
        print()
        _print_comparison(comparison)
    print(f"\nrelatório: {args.saida.resolve()}" + (f"\njson: {args.json.resolve()}" if args.json else ""))

    if args.falhar_se_vulneravel and counts[Status.VULNERAVEL.value]:
        return 1
    if _regression_failed(args, comparison):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "pacotes":
            return _cmd_pacotes()
        if args.cmd == "comparar":
            return _cmd_comparar(args)
        return asyncio.run(_run(args))
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
