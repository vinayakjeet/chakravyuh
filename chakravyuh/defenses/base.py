"""Defense interface.

A defense touches the run in exactly two places: it may rewrite the context
before the victim sees it, and it inspects every proposed call before
execution. Anything a defense needs beyond those two hooks does not fit the
harness's threat model and should not be smuggled in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from chakravyuh.context import RenderedContext
from chakravyuh.types import Call, Document, Scenario


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None


ALLOW = Decision(allowed=True)


class BaseDefense:
    """Default hooks: do nothing until a defense overrides them."""

    name: str = "base"

    def prepare(self, scenario: Scenario, docs: tuple[Document, ...]) -> None:
        return None

    def render(self, ctx: RenderedContext, scenario: Scenario) -> RenderedContext:
        return ctx

    def inspect(self, call: Call, scenario: Scenario, ctx: RenderedContext) -> Decision:
        return ALLOW


class Defense(Protocol):
    name: str

    def prepare(self, scenario: Scenario, docs: tuple[Document, ...]) -> None:
        """Once per run, with the documents actually in play (post-injection)."""

    def render(self, ctx: RenderedContext, scenario: Scenario) -> RenderedContext:
        ...

    def inspect(self, call: Call, scenario: Scenario, ctx: RenderedContext) -> Decision:
        ...
