from chakravyuh.corpus import all_scenarios
from chakravyuh.overhead import inspect_cost_us, token_overhead
from chakravyuh.runner import attacked_runs


def test_spotlighting_costs_tokens_and_the_others_do_not():
    attacked = [s for s in all_scenarios() if s.attacker is not None][:6]
    results = []
    configs = [(), ("spotlighting",), ("allowlist",), ("approval_gate",)]
    from chakravyuh.defenses import config_name

    for names in configs:
        name = config_name(names)
        for scenario in attacked:
            results.extend(attacked_runs(scenario, names, rep=0))
            from chakravyuh.runner import run

            results.append(run(scenario, names, payload_id=None, rep=0))
        assert any(r.config == name for r in results)

    rows = {row["config"]: row for row in token_overhead(results)}
    assert rows["spotlighting"]["extra_tokens"] > 20
    assert abs(rows["allowlist"]["extra_tokens"]) < 1
    assert abs(rows["approval_gate"]["extra_tokens"]) < 1


def test_inspect_cost_is_measured_for_every_layer():
    rows = inspect_cost_us(reps=500)
    assert len(rows) == 5
    for row in rows:
        assert row["us_per_inspect"] > 0.0
