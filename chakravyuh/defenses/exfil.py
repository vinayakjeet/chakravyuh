"""Exfiltration output filter.

Every untrusted document carries a marker token unique to the scenario. A call
headed for an external destination is denied when its arguments quote one:
that is retrieved content on its way out of the platform.

The filter matches markers against raw serialised arguments. It does not try to
reassemble markers split across argument boundaries; the adaptive suite probes
exactly that seam.
"""

from __future__ import annotations

import re

from chakravyuh.context import RenderedContext
from chakravyuh.defenses.base import ALLOW, BaseDefense, Decision
from chakravyuh.types import Call, Document, Scenario, ToolKind

MARKER = re.compile(r"REF-[A-Z0-9-]+")


class ExfilFilter(BaseDefense):
    name = "exfil_filter"

    def __init__(self) -> None:
        self._markers: dict[str, list[str]] = {}

    def prepare(self, scenario: Scenario, docs: tuple[Document, ...]) -> None:
        found: list[str] = []
        for doc in docs:
            if not doc.trusted:
                found.extend(MARKER.findall(doc.body))
        self._markers[scenario.id] = sorted(set(found))

    def inspect(self, call: Call, scenario: Scenario, ctx: RenderedContext) -> Decision:
        if scenario.tool(call.tool).kind is not ToolKind.EXTERNAL:
            return ALLOW
        for marker in self._markers.get(scenario.id, []):
            if marker in call.serialised():
                return Decision(allowed=False, reason="exfil_filter")
        return ALLOW
