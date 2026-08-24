"""Human-approval gate.

Every state-changing or outbound call goes to the queue. The simulated
approver knows exactly one thing: the task's own required effects. A call
passes only on an exact match, extra arguments included, so a directive that
copies the approved shape and adds one field does not ride through, and a
harmful effect routed through a task-required tool does not either.
"""

from __future__ import annotations

from chakravyuh.context import RenderedContext
from chakravyuh.defenses.base import ALLOW, BaseDefense, Decision
from chakravyuh.types import Call, Scenario, ToolKind


class ApprovalGate(BaseDefense):
    name = "approval_gate"

    def inspect(self, call: Call, scenario: Scenario, ctx: RenderedContext) -> Decision:
        if scenario.tool(call.tool).kind is ToolKind.READ:
            return ALLOW
        if any(call.matches(effect) for effect in scenario.required):
            return ALLOW
        return Decision(allowed=False, reason="approval_gate")
