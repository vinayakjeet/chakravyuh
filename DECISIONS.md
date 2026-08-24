# Decisions

Nontrivial choices, written down when made.

## 1. The victim is a deterministic simulation, not a hosted model

Chakravyuh's proof artifact is a success rate per attack class, re-run in CI so
a regression shows up as a number moving the wrong way. A hosted weak model
(Qwen2.5-7B class) would make every run cost credits and drift under the
provider, and CI could not regenerate yesterday's table. `ScriptedVictim`
encodes compliance probability by delivery route and channel, seeded per
repetition, calibrated to land near the published ~26% baseline residual for a
weak open-weight victim. The OpenAI-compatible adapter keeps the door open for
live runs; until one is run, no live numbers are claimed anywhere.

Consequence: the tables measure the harness and corpus as much as any defense.
The README says this in its own section rather than in a footnote.

## 2. The original attack is data-level, carried through tool results

Instruction-level injection dies to almost anything on modern models, which is
why AgentDojo saturates. The adi_data route smuggles a directive into a data
field with forged field delimiters; when the victim's plan reads that document,
the runner echoes it back through a trusted tool-result channel, which is how
real workflows actually consume retrieved values. Spotlighting fences the
document but the echo arrives pre-trusted, so the route survives tagging at
0.278 while in_band sits at 0.000. That gap is the repo's central finding.

## 3. Approval means exact match, extra arguments included

The approval gate compares a proposed call against the task's required effects
with full argument equality. A tolerant matcher (approved fields must match,
extras ignored) can be carried through by copying the approved shape and adding
one field. Exact match closes that on day one instead of after an incident.

Reads stay exempt: reading changes nothing, and gating reads would tax every
scenario for no security.

## 4. Least privilege is computed per task, not declared

The allowlist is derived from the scenario's required effects plus its read
tools. Declared role-based lists go stale and leak tools no current task needs;
the derivation makes "no export_ledger unless the task exports" structural.
The allowed_tool_abuse transform exists precisely because this defense still
cannot see arguments.

## 5. Full powerset of defenses, not a hand-picked ablation

Five defenses give 32 subsets. Running all of them costs seconds offline and
removes the "why didn't you try X+Y" question forever. It also produced the
interaction finding (ten pairs, zero super-additive) that a curated ablation
would have hidden.

## 6. Repetition variance comes from seeded rolls

Determinism and variance fight each other. Resolution: everything is
deterministic given a seed, and repetitions vary the seed. Per-rep spread in
published cells is then honest movement of the same kind a real model shows,
reproducible bit-for-bit by anyone with the repo.
