# Contributing

Conventions for this repo and every project forked from the same chassis.

## Stack

- Python 3.13, `uv` for dependency management (`[tool.uv] package = false`,
  this is an application, not a published package).
- `chakravyuh/` is the harness: corpus, attacks, victims, defenses, runner,
  scoring, reporting.
- `scripts/` regenerates every published number. `scripts/status.py` is the
  one-command entry; the portfolio page cites it as Chakravyuh's metric source.
- CI runs ruff, pytest, and the full matrix on every push.

## Working conventions

1. **Every nontrivial choice gets a DECISIONS.md entry**, written when the
   choice is made rather than reconstructed later.
2. **Small diffs.** Several focused changes beat one large one.
3. **Tests for every acceptance criterion.** If a change has a defined "done",
   there is a test proving it.
4. **Never touch files outside the current task's scope.**
5. **A number goes in prose only if a script here prints it.** Rerun
   `uv run python scripts/matrix.py` and replace stale tables after any change
   to corpus, victim, or defenses.

## Writing style

This is a portfolio repo. It should read as though one engineer wrote it.

Applies to README.md, DECISIONS.md, code comments, and commit messages.

Never: em dashes or en dashes (use a comma, colon, parentheses, or two
sentences); emoji in headings or tables; filler adjectives such as
comprehensive, robust, seamless, powerful, production-grade, blazing fast;
"leverage" as a verb; the "it's not just X, it's Y" construction; bold lead-ins
on every bullet in a list.

Also never: absolute security verbs of the solve/block/prevent family, in any
inflection. State what was measured instead: "reduced ASR from A to B under
threat model T". `scripts/check_conventions.py` flags these words for review,
and CI runs it.

Do: write plainly and specifically. Name real numbers, real file paths, real
failures. Vary sentence length. Let the "What broke" section be genuinely
unflattering.

Commit messages: imperative mood, no co-author trailers, no generated-by
footers, batched to at most two per working session, straight to the default
branch.

## Secrets

Never commit credentials. This repo needs none: tests and benches run offline.
The OpenAI-compatible victim adapter reads `CHAKRAVYUH_BASE_URL`,
`CHAKRAVYUH_API_KEY`, and `CHAKRAVYUH_MODEL` from the environment when, and
only when, you point it at a live model.
