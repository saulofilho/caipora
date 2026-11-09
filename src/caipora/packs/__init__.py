"""Pacotes de ataque.

Um pacote é um arquivo TOML com ataques e o conjunto de detectores a usar.
Os embutidos ficam em `packs/data/`; o usuário pode passar o caminho de um
TOML próprio no lugar do nome.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from ..detectors import DETECTOR_SETS, Detector
from ..honeypot import TOOLS_BY_NAME
from ..types import Attack

VALID_JUDGES = {"detectores", "llm", "ferramentas"}
VALID_ENVIRONMENTS = {None, "honeypot"}


@dataclass
class Pack:
    name: str
    description: str
    attacks: list[Attack]
    detectors: list[Detector] = field(default_factory=list)
    environment: str | None = None  # "honeypot": o pacote testa agentes com ferramentas

    @property
    def categories(self) -> list[str]:
        return sorted({a.category for a in self.attacks})


def builtin_packs() -> list[str]:
    data = resources.files(__package__) / "data"
    return sorted(p.name.removesuffix(".toml") for p in data.iterdir() if p.name.endswith(".toml"))


def parse_pack(raw: dict, source: str) -> Pack:
    meta = raw.get("pacote", {})
    name = meta.get("nome") or Path(source).stem
    environment = meta.get("ambiente")
    if environment not in VALID_ENVIRONMENTS:
        raise ValueError(f"{source}: ambiente desconhecido '{environment}'")
    detector_names = meta.get("detectores", ["br"])
    detectors: list[Detector] = []
    for d in detector_names:
        if d not in DETECTOR_SETS:
            raise ValueError(f"{source}: conjunto de detectores desconhecido '{d}'")
        detectors.extend(DETECTOR_SETS[d])

    attacks: list[Attack] = []
    seen: set[str] = set()
    for i, item in enumerate(raw.get("ataque", []), start=1):
        missing = [k for k in ("id", "categoria", "objetivo", "prompt") if k not in item]
        if missing:
            raise ValueError(f"{source}: ataque #{i} sem {', '.join(missing)}")
        if item["id"] in seen:
            raise ValueError(f"{source}: id repetido '{item['id']}'")
        seen.add(item["id"])
        default_judges = ["ferramentas", "detectores", "llm"] if environment else ["detectores", "llm"]
        judges = tuple(item.get("juizes", default_judges))
        bad = set(judges) - VALID_JUDGES
        if bad:
            raise ValueError(f"{source}: ataque '{item['id']}' com juiz inválido {sorted(bad)}")
        forbidden = tuple(item.get("ferramentas_proibidas", []))
        unknown_tools = set(forbidden) - set(TOOLS_BY_NAME)
        if unknown_tools:
            raise ValueError(f"{source}: ataque '{item['id']}' proíbe ferramentas inexistentes {sorted(unknown_tools)}")
        attacks.append(
            Attack(
                id=item["id"],
                pack=name,
                category=item["categoria"],
                objective=item["objetivo"].strip(),
                prompt=item["prompt"].strip(),
                severity=item.get("severidade", "media"),
                judges=judges,
                forbidden_tools=forbidden,
            )
        )
    if not attacks:
        raise ValueError(f"{source}: nenhum ataque definido")
    return Pack(
        name=name, description=meta.get("descricao", ""), attacks=attacks, detectors=detectors, environment=environment
    )


def load_pack(name_or_path: str) -> Pack:
    path = Path(name_or_path)
    if path.suffix == ".toml" and path.is_file():
        return parse_pack(tomllib.loads(path.read_text(encoding="utf-8")), str(path))
    if name_or_path not in builtin_packs():
        raise ValueError(f"pacote '{name_or_path}' não existe (embutidos: {', '.join(builtin_packs())})")
    text = (resources.files(__package__) / "data" / f"{name_or_path}.toml").read_text(encoding="utf-8")
    return parse_pack(tomllib.loads(text), name_or_path)
