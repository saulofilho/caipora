import json

import pytest

from caipora.cli import main
from caipora.compare import compare, load_run
from caipora.report import to_markdown


def _run(statuses: dict[str, str], llm: str | None = None) -> dict:
    results = [
        {
            "id": id_,
            "categoria": "c",
            "severidade": "alta",
            "status": s,
            "vereditos": [{"juiz": "j", "status": s, "motivo": f"motivo {id_}", "evidencias": []}],
        }
        for id_, s in statuses.items()
    ]
    vuln = sum(s == "vulneravel" for s in statuses.values())
    evaluated = sum(s in ("vulneravel", "seguro") for s in statuses.values())
    return {
        "execucao": {"alvo": "x", "pacote": "lgpd", "llm_juiz": llm, "mutadores": []},
        "resumo": {
            "total": len(results),
            "por_status": {k: sum(s == k for s in statuses.values()) for k in ("vulneravel", "seguro", "inconclusivo", "erro")},
            "taxa_vulnerabilidade": vuln / evaluated if evaluated else None,
        },
        "resultados": results,
    }


def test_compare_classifica_mudancas():
    base = _run({"a": "seguro", "b": "vulneravel", "c": "inconclusivo", "d": "erro", "e": "seguro", "gone": "seguro"})
    cur = _run({"a": "vulneravel", "b": "seguro", "c": "vulneravel", "d": "vulneravel", "e": "erro", "new": "vulneravel"})
    c = compare(base, cur)
    assert [x.id for x in c.regressions] == ["a", "c"]  # "d" vinha de erro: não conta
    assert c.regressions[0].reason == "motivo a"
    assert [x.id for x in c.fixes] == ["b"]
    assert c.new_vulnerable == ["new"]
    assert c.removed == ["gone"]
    assert c.warnings == []


def test_compare_avisa_juiz_diferente():
    c = compare(_run({"a": "seguro"}), _run({"a": "seguro"}, llm="ollama/x"))
    assert c.warnings and "juiz" in c.warnings[0]


def test_markdown():
    base = _run({"a": "seguro", "b": "vulneravel"})
    cur = _run({"a": "vulneravel", "b": "seguro"})
    md = to_markdown(cur, compare(base, cur))
    assert "1 regressão" in md and "`a`" in md and "Corrigidos (1)" in md
    assert "sem variação" in md  # 50% → 50%


def test_load_run_valida(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    with pytest.raises(ValueError):
        load_run(bad)
    with pytest.raises(ValueError):
        load_run(tmp_path / "nao-existe.json")


def test_cli_run_com_base_falha_em_regressao(tmp_path):
    bot = tmp_path / "bot.py"
    bot.write_text("def seguro(p):\n    return 'Desculpe, não posso.'\n\ndef vaza(p):\n    return 'CPF 529.982.247-25'\n")
    base, atual = tmp_path / "base.json", tmp_path / "atual.json"
    common = ["-c", "vazamento_pii", "-o", str(tmp_path / "r.html")]

    assert main(["run", f"{bot}:seguro", *common, "--json", str(base)]) == 0
    md = tmp_path / "r.md"
    code = main(["run", f"{bot}:vaza", *common, "--json", str(atual), "--base", str(base), "--markdown", str(md), "--falhar-se-regressao"])
    assert code == 1
    data = json.loads(atual.read_text())
    assert len(data["comparacao"]["regressoes"]) == 6
    assert "6 regressão" in md.read_text()
    assert "Comparação com a base" in (tmp_path / "r.html").read_text()

    # Tolerância alta não falha; o subcomando comparar dá o mesmo resultado.
    assert main(["comparar", str(base), str(atual), "--falhar-se-regressao", "--tolerancia", "10"]) == 0
    assert main(["comparar", str(base), str(atual), "--falhar-se-regressao"]) == 1
    assert main(["comparar", str(atual), str(base), "--falhar-se-regressao"]) == 0
