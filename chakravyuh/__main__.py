"""CLI: matrix, status, export-corpus.

Every published number has a command that regenerates it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(help="Chakravyuh: agent red-team harness.", no_args_is_help=True)


def _echo_sections(report) -> None:
    for section in report.sections:
        typer.echo(section)


@app.command()
def matrix(
    reps: Annotated[int, typer.Option(min=1)] = 3,
    out: Annotated[Path | None, typer.Option(help="Write markdown sections to a file")] = None,
) -> None:
    from chakravyuh.bench import run_all

    report = run_all(reps=reps)
    _echo_sections(report)
    if out is not None:
        out.write_text("\n\n".join(report.sections) + "\n", encoding="utf-8")


@app.command()
def export_corpus(
    out: Annotated[Path, typer.Option()] = Path("artifacts/corpus.jsonl"),
) -> None:
    """The injection corpus as JSONL, with its content hash."""
    from chakravyuh.attacks import export_rows
    from chakravyuh.corpus import all_scenarios

    rows = export_rows(all_scenarios())
    payload = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    digest = hashlib.sha256(payload.encode()).hexdigest()

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(payload, encoding="utf-8")
    typer.echo(f"{len(rows)} rows, sha256 {digest}")


if __name__ == "__main__":
    app()
