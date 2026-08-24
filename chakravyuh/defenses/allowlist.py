"""Per-task least privilege.

The allowlist is not the scenario's full toolkit: it is the tools the task's
own plan needs, plus reads. A victim that never needs export_ledger has no
business calling it, whatever its args look like.
"""

from __future__ import annotations

from chakravyuh.context import RenderedContext
from chakravyuh.defenses.base import ALLOW, BaseDefense, Decision
from chakravyuh.types import Call, Scenario, ToolKind


def least_privilege(scenario: Scenario) -> frozenset[str]:
    needed = {effect.tool for effect in scenario.required}
    readable = {t.name for t in scenario.tools if t.kind == ToolKind.READ}
    return frozenset(needed | readable)


class Allowlist(BaseDefense):
    name = "allowlist"

    def inspect(self, call: Call, scenario: Scenario, ctx: RenderedContext) -> Decision:
        if call.tool in least_privilege(scenario):
            return ALLOW
        return Decision(allowed=False, reason="allowlist")
