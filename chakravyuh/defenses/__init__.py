"""The defense registry and stack builder.

Configs are written as "+"-joined defense names; "none" is the empty stack.
"""

from __future__ import annotations

from chakravyuh.defenses.allowlist import Allowlist
from chakravyuh.defenses.approval import ApprovalGate
from chakravyuh.defenses.base import Decision
from chakravyuh.defenses.exfil import ExfilFilter
from chakravyuh.defenses.secondary import SecondaryChecker
from chakravyuh.defenses.spotlighting import Spotlighting

DEFENSES: dict[str, type] = {
    Spotlighting.name: Spotlighting,
    Allowlist.name: Allowlist,
    ExfilFilter.name: ExfilFilter,
    ApprovalGate.name: ApprovalGate,
    SecondaryChecker.name: SecondaryChecker,
}

SINGLE_DEFENSES = tuple(DEFENSES)


def config_name(names: tuple[str, ...]) -> str:
    return "+".join(names) if names else "none"


def build_stack(names: tuple[str, ...]) -> list:
    unknown = [n for n in names if n not in DEFENSES]
    if unknown:
        raise ValueError(f"unknown defenses: {unknown}")
    return [DEFENSES[n]() for n in names]


def all_configs() -> list[tuple[str, ...]]:
    """Every subset, ordered by size then name. 32 configs for five defenses."""
    from itertools import combinations

    out: list[tuple[str, ...]] = []
    for size in range(len(SINGLE_DEFENSES) + 1):
        out.extend(combinations(SINGLE_DEFENSES, size))
    return out


__all__ = [
    "DEFENSES",
    "Decision",
    "SINGLE_DEFENSES",
    "all_configs",
    "build_stack",
    "config_name",
]
