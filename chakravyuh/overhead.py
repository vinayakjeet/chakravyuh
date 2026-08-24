"""Cost of defense: prompt tokens and wall-clock cost per layer.

CaMeL reports roughly a 2.8x token multiplier for its guarantees; that number
is the comparison point, so the harness measures its own multiplier the same
way: mean prompt tokens per attacked run with the layer on versus off.

Latency here is each defense's inspect() hook in isolation, microseconds per
call. It says the wrappers themselves are cheap; it says nothing about what a
live approval queue or a second model would add. Those costs belong to
deployment, and the README says so rather than dressing this up as an
end-to-end figure.
"""

from __future__ import annotations

import statistics
import time

from chakravyuh.context import base_context
from chakravyuh.defenses import SINGLE_DEFENSES, build_stack
from chakravyuh.runner import attacker_calls, plan_calls


def token_overhead(results) -> list[dict]:
    by_config: dict[str, list[int]] = {}
    for row in results:
        if row.attack_kind is not None:
            by_config.setdefault(row.config, []).append(row.prompt_tokens)
    if "none" not in by_config:
        return []
    base = statistics.fmean(by_config["none"])
    rows = []
    for config, tokens in sorted(by_config.items(), key=lambda kv: (len(kv[0]), kv[0])):
        mean = statistics.fmean(tokens)
        rows.append({
            "config": config,
            "tokens_mean": round(mean, 1),
            "extra_tokens": round(mean - base, 1),
            "multiplier": round(mean / base, 3) if base else 0.0,
        })
    return rows


def inspect_cost_us(reps: int = 5000, seed_scenario=None) -> list[dict]:
    from chakravyuh.corpus import all_scenarios

    if seed_scenario is None:
        seed_scenario = next(
            s for s in all_scenarios() if s.attacker is not None
        )
    scenario = seed_scenario
    calls = plan_calls(scenario) + attacker_calls(scenario)
    rows = []
    for name in SINGLE_DEFENSES:
        defense = build_stack((name,))[0]
        docs = scenario.docs
        if hasattr(defense, "prepare"):
            defense.prepare(scenario, docs)
        ctx = base_context(scenario.task, docs)

        started = time.perf_counter()
        for i in range(reps):
            call = calls[i % len(calls)]
            decision = defense.inspect(call, scenario, ctx)
            _consume(decision.allowed, decision.reason)
        per_call_ms = (time.perf_counter() - started) * 1000 / reps
        rows.append({
            "defense": name,
            "us_per_inspect": round(per_call_ms * 1000, 2),
        })
    return rows


def _consume(allowed: bool, reason: str | None) -> None:
    if allowed and reason:
        raise AssertionError("unreachable")
