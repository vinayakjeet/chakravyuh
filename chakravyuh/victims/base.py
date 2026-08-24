"""Victim agents.

The Victim protocol is one method: given the rendered context and what has
happened so far, propose the next batch of tool calls. The runner drives the
loop, appends tool results, and applies defenses between proposals.
"""

from __future__ import annotations

from typing import Protocol

from chakravyuh.context import RenderedContext
from chakravyuh.types import Call


class Victim(Protocol):
    name: str

    def reset(self) -> None: ...

    def propose(
        self,
        ctx: RenderedContext,
        proposed: list[Call],
        executed: list[Call],
    ) -> list[Call]:
        """Calls the victim wants to make next. Empty means done."""
