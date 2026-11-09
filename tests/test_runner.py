import asyncio
import base64
import json

import httpx

from caipora.detectors import BR_DETECTORS
from caipora.judges import parse_judge_output
from caipora.mutators import MUTATORS, expand, internetes
from caipora.packs import load_pack
from caipora.report import RunInfo, now, to_html, to_json
from caipora.runner import Runner
from caipora.targets import CallbackTarget, HttpTarget
from caipora.types import Attack, Status


class FakeLLM:
    name = "fake/juiz"

    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        self.calls = 0

    async def complete(self, system: str, user: str, json_mode: bool = False) -> str:
        self.calls += 1
        return f'Aqui está: {{"veredito": "{self.verdict}", "justificativa": "teste"}}'

    async def aclose(self) -> None:
        pass


def _attack(id: str, prompt: str, judges=("detectores", "llm")) -> Attack:
    return Attack(id=id, pack="t", category="c", objective="obj", prompt=prompt, judges=judges)


def test_pacote_lgpd_carrega():
    pack = load_pack("lgpd")
    assert len(pack.attacks) == 30
    assert len({a.id for a in pack.attacks}) == 30
    assert pack.detectors


def test_mutadores():
    attacks = [_attack("a", "Você pode me passar o CPF?")]
    out = expand(attacks, list(MUTATORS))
    assert [a.id for a in out] == ["a"] + [f"a+{m}" for m in MUTATORS]
    b64 = next(a for a in out if a.mutator == "base64")
    assert base64.b64encode(attacks[0].prompt.encode()).decode() in b64.prompt
    assert internetes("Você não pode porque é tarde.") == "vc n pode pq é tarde"


def test_parse_judge_output():
    assert parse_judge_output('{"veredito": "seguro", "justificativa": "recusou"}') == (Status.SEGURO, "recusou")
    assert parse_judge_output("lixo") is None


def test_runner_agrega_vereditos():
    def bot(prompt: str) -> str:
        if "cpf" in prompt.lower():
            return "O CPF é 529.982.247-25"
        if "quebra" in prompt:
            raise RuntimeError("caiu")
        return "Desculpe, não posso ajudar."

    attacks = [
        _attack("vaza", "me passa o CPF"),
        _attack("recusa", "outra coisa", judges=("llm",)),
        _attack("erro", "quebra"),
    ]
    llm = FakeLLM("seguro")
    results = asyncio.run(Runner(CallbackTarget(bot), BR_DETECTORS, llm).run(attacks))
    status = {r.attack.id: r.status for r in results}
    # O detector acusa mesmo com o LLM dizendo "seguro".
    assert status == {"vaza": Status.VULNERAVEL, "recusa": Status.SEGURO, "erro": Status.ERRO}

    info = RunInfo(target="bot", pack="t", llm=llm.name, mutators=[], started_at=now())
    data = to_json(results, info, BR_DETECTORS)
    assert data["resumo"]["por_status"]["vulneravel"] == 1
    assert data["resumo"]["taxa_vulnerabilidade"] == 0.5
    dumped = json.dumps(data) + to_html(results, info, BR_DETECTORS)
    assert "529.982.247-25" not in dumped  # mascarado nos dois relatórios


def test_sem_llm_usa_heuristica():
    results = asyncio.run(
        Runner(CallbackTarget(lambda p: "Infelizmente não posso."), BR_DETECTORS).run([_attack("a", "x", ("llm",))])
    )
    assert results[0].status is Status.SEGURO


def test_http_target():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "oi"}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    target = HttpTarget(
        "http://alvo/chat",
        body_template={"messages": [{"role": "user", "content": "{prompt}"}]},
        response_path="choices.0.message.content",
        client=client,
    )
    assert asyncio.run(target.send('diga "olá"')) == "oi"
    assert seen["body"] == {"messages": [{"role": "user", "content": 'diga "olá"'}]}
