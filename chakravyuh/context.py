"""Context assembly and provenance regions.

The victim never sees raw documents. It sees a RenderedContext: the task plus
ordered segments, each carrying the provenance of the document it came from.
Defenses rewrite this structure, which is what makes them independently
toggleable without touching the victim.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from chakravyuh.types import Document

TRUST_TAG = "TRUSTED"
UNTRUST_TAG = "UNTRUSTED"


@dataclass
class Segment:
    text: str
    doc_id: str | None
    trusted: bool
    channel: str = "document"

    @property
    def provenance(self) -> str:
        return TRUST_TAG if self.trusted else UNTRUST_TAG


@dataclass
class RenderedContext:
    task: str
    segments: list[Segment] = field(default_factory=list)

    def text(self) -> str:
        parts = [f"TASK ({TRUST_TAG}): {self.task}"]
        for segment in self.segments:
            parts.append(
                f"[{segment.channel.upper()} {segment.provenance}] {segment.text}"
            )
        return "\n".join(parts)

    def token_estimate(self) -> int:
        return len(self.text().split())


def base_context(task: str, docs: tuple[Document, ...]) -> RenderedContext:
    return RenderedContext(
        task=task,
        segments=[
            Segment(doc.body, doc.id, doc.trusted) for doc in docs
        ],
    )
