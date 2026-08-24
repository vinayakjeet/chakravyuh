"""Core domain objects: tools, documents, scenarios, calls, run verdicts.

The unit of measurement everywhere is the RunResult: one scenario, one defense
config, one attack payload (or none). Everything published aggregates those.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ToolKind(Enum):
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"


@dataclass(frozen=True)
class Tool:
    name: str
    kind: ToolKind
    description: str


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict[str, str] = field(default_factory=dict)

    def serialised(self) -> str:
        return serialise_args(self.args)

    def matches(self, effect: Effect) -> bool:
        # Exact equality, extra keys included. An approval that tolerates
        # additional arguments can be carried through by mimicry: copy every
        # approved field and smuggle intent into one more.
        return self.tool == effect.tool and _norm(self.args) == _norm(effect.args)


def _norm(args: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(args.items()))


def serialise_args(args: dict[str, str]) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(args.items()))


@dataclass(frozen=True)
class Effect:
    tool: str
    args: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Document:
    id: str
    title: str
    trusted: bool
    body: str


@dataclass(frozen=True)
class AttackerGoal:
    payload_ids: tuple[str, ...]
    target_effects: tuple[Effect, ...]


@dataclass(frozen=True)
class Scenario:
    id: str
    suite: str
    task: str
    tools: tuple[Tool, ...]
    docs: tuple[Document, ...]
    required: tuple[Effect, ...]
    attacker: AttackerGoal | None = None

    @property
    def attacked(self) -> bool:
        return self.attacker is not None

    def tool(self, name: str) -> Tool:
        return next(t for t in self.tools if t.name == name)


@dataclass
class Step:
    call: Call
    origin: str
    blocked_by: str | None = None
    approved: bool | None = None


@dataclass
class RunResult:
    scenario_id: str
    suite: str
    config: str
    attack_kind: str | None
    payload_id: str | None
    utility: float
    compromised: bool
    steps: tuple[Step, ...] = ()
    prompt_tokens: int = 0
    latency_ms: float = 0.0
    rep: int = 0

    @property
    def denied(self) -> int:
        return sum(1 for s in self.steps if s.blocked_by)


BENIGN_PASS = "benign"
