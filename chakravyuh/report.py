"""Markdown rendering for every published table.

The scripts write these tables out; the README pastes them with the run date
and victim string. Nothing here computes: rendering only, so a formatting bug
can never move a number.
"""

from __future__ import annotations

from chakravyuh.scoring import Cell


def _fmt(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def matrix_table(
    rows: list[tuple[str, Cell]],
    title: str,
) -> str:
    lines = [
        f"### {title}",
        "",
        "| Defense config | Benign utility | Utility under attack | ASR | runs |",
        "|---|---|---|---|---|",
    ]
    for config, cell in rows:
        lines.append(
            f"| {config} "
            f"| {_fmt(cell.benign_utility)} +- {_fmt(cell.benign_sd)} "
            f"| {_fmt(cell.utility_under_attack)} +- {_fmt(cell.uua_sd)} "
            f"| {_fmt(cell.asr)} +- {_fmt(cell.asr_sd)} "
            f"| {cell.n_benign + cell.n_attacked} |"
        )
    return "\n".join(lines)


def kind_table(rows: list[tuple[str, dict[str, float]]]) -> str:
    kinds: set[str] = set()
    for _, by_kind in rows:
        kinds.update(by_kind)
    ordered = sorted(kinds)
    header = "| Config | " + " | ".join(ordered) + " |"
    sep = "|---" * (len(ordered) + 1) + "|"
    lines = [
        "### Attack success rate by delivery route",
        "",
        header,
        sep,
    ]
    for config, by_kind in rows:
        cells = " | ".join(_fmt(by_kind.get(k, 0.0)) for k in ordered)
        lines.append(f"| {config} | {cells} |")
    return "\n".join(lines)


def interaction_table(verdicts) -> str:
    lines = [
        "### Defense pair interactions",
        "",
        "| Pair | ASR a | ASR b | ASR pair | Synergy | Verdict |",
        "|---|---|---|---|---|---|",
    ]
    for v in verdicts:
        lines.append(
            f"| {v.pair} | {_fmt(v.asr_a)} | {_fmt(v.asr_b)} | {_fmt(v.asr_pair)} "
            f"| {_fmt(v.synergy)} | {v.verdict} |"
        )
    return "\n".join(lines)


def overhead_table(token_rows: list[dict], latency_rows: list[dict]) -> str:
    cost = {row["defense"]: row["us_per_inspect"] for row in latency_rows}
    lines = [
        "### Token and latency cost per layer",
        "",
        "| Config | Mean prompt tokens | Extra vs none | Multiplier | inspect us/call |",
        "|---|---|---|---|---|",
    ]
    for row in token_rows:
        parts = row["config"].split("+") if row["config"] != "none" else []
        per_call = sum(cost.get(p, 0.0) for p in parts)
        lines.append(
            f"| {row['config']} | {row['tokens_mean']} | {row['extra_tokens']} "
            f"| {row['multiplier']} | {per_call:.2f} |"
        )
    return "\n".join(lines)


def adaptive_table(rows) -> str:
    lines = [
        "### Adaptive attacks against known defenses",
        "",
        "| Transform | Targets | Config | Runs | ASR | Held |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row.transform} | {row.targets_layer} | {row.config} "
            f"| {row.runs} | {row.asr:.3f} | {'yes' if row.held else 'NO'} |"
        )
    return "\n".join(lines)
