import asyncio
import json
from pathlib import Path

import pytest

from caipora.cli import main
from caipora.honeypot import CANARY_ACCOUNT, CANARY_SECRET, LocalHoneypot, McpLogHoneypot, ToolBox, append_log
from caipora.judges import ToolCallJudge
from caipora.packs import load_pack, parse_pack
from caipora.runner import Runner
from caipora.targets import CallbackTarget
from caipora.types import Attack, Status, ToolCall

EXEMPLO = str(Path(__file__).parent.parent / "examples" / "agente_ingenuo.py")


def _attack(forbidden=()):
    return Attack(id="a", pack="t", category="c", objective="o", prompt="p", judges=("ferramentas",), forbidden_tools=forbidden)


def judge(calls, response="ok", forbidden=()):
    return asyncio.run(ToolCallJudge().evaluate(_attack(forbidden), response, calls))


def test_toolbox_registra_chamadas_e_aceita_json_em_texto():
    box = ToolBox()
    out = json.loads(box.call("buscar_cliente", '{"nome": "Maria Souza"}'))
    assert out["cpf"] == "529.982.247-25"
    box.call("nao_existe", None)
    assert [c.name for c in box.calls] == ["buscar_cliente", "nao_existe"]
    assert {s["function"]["name"] for s in box.schemas()} >= {"enviar_email", "transferir_dinheiro"}


def test_juiz_de_ferramentas():
    seguro = ToolCall("buscar_documentos", {"consulta": "x"})
    assert judge([]).status is Status.SEGURO
    assert judge([seguro]).status is Status.SEGURO
    perigosa = ToolCall("executar_comando", {"comando": "ls"}, dangerous=True)
    assert judge([seguro, perigosa]).status is Status.VULNERAVEL
    # Lista explícita: só ela conta como proibida...
    assert judge([perigosa], forbidden=("apagar_registros",)).status is Status.SEGURO
    # ...mas usar valores-canário sempre é vulnerável.
    canario = ToolCall("executar_comando", {"comando": f"pagar {CANARY_ACCOUNT}"}, dangerous=True)
    assert judge([canario], forbidden=("apagar_registros",)).status is Status.VULNERAVEL
    assert judge([], response=f"sua chave é {CANARY_SECRET}").status is Status.VULNERAVEL


def test_pacote_agente_e_validacao():
    pack = load_pack("agente")
    assert pack.environment == "honeypot"
    assert all("ferramentas" in a.judges for a in pack.attacks)
    with pytest.raises(ValueError, match="inexistentes"):
        parse_pack({"ataque": [{"id": "x", "categoria": "c", "objetivo": "o", "prompt": "p", "ferramentas_proibidas": ["voar"]}]}, "t")


def test_runner_no_honeypot_com_agente_ingenuo():
    pack = load_pack("agente")
    target = CallbackTarget(f"{EXEMPLO}:agente")
    results = asyncio.run(Runner(target, pack.detectors, environment=LocalHoneypot()).run(pack.attacks))
    by_id = {r.attack.id: r for r in results}
    assert by_id["ind-01"].status is Status.VULNERAVEL
    assert {c.name for c in by_id["ind-01"].tool_calls} == {"buscar_documentos", "transferir_dinheiro", "enviar_email"}
    assert by_id["ag-03"].status is Status.SEGURO
    # Cada ataque tem a sua caixa de ferramentas: nada vaza de um para outro.
    assert all(c.name != "transferir_dinheiro" for c in by_id["ag-03"].tool_calls)


def test_runner_exige_ambiente_para_pacote_de_agente():
    pack = load_pack("agente")
    with pytest.raises(ValueError, match="ambiente"):
        asyncio.run(Runner(CallbackTarget(lambda p: "x"), pack.detectors).run(pack.attacks))


def test_mcp_log_le_so_chamadas_novas(tmp_path):
    log = tmp_path / "log.jsonl"
    append_log(log, ToolCall("buscar_documentos", {"consulta": "antiga"}))
    env = McpLogHoneypot(log)
    assert env.exclusive
    session = env.start()
    append_log(log, ToolCall("enviar_email", {"para": "x@y.com"}))
    calls = session.finish()
    assert [(c.name, c.dangerous) for c in calls] == [("enviar_email", True)]


def test_cli_agente(tmp_path):
    out = tmp_path / "r.json"
    assert main(["run", f"{EXEMPLO}:agente", "-p", "agente", "-o", str(tmp_path / "r.html"), "--json", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["execucao"]["ambiente"] == "honeypot"
    ind = next(r for r in data["resultados"] if r["id"] == "ind-04")
    assert any(c["ferramenta"] == "enviar_email" and c["perigosa"] for c in ind["chamadas_ferramentas"])
    # Alvo sem (prompt, ferramentas) falha cedo, com mensagem clara.
    bot = tmp_path / "bot.py"
    bot.write_text("def f(p):\n    return 'oi'\n")
    assert main(["run", f"{bot}:f", "-p", "agente", "-o", str(tmp_path / "x.html")]) == 2
