from chakravyuh.corpus import all_scenarios
from chakravyuh.interaction import classify
from chakravyuh.scoring import cell_for, collect


def test_pairs_are_classified_and_synergy_math_consistent():
    scenarios = [s for s in all_scenarios() if s.attacker is not None][:6]
    from chakravyuh.runner import run

    results = []
    for rep in range(3):
        configs = [
            (),
            ("allowlist",),
            ("approval_gate",),
            ("allowlist", "approval_gate"),
            ("spotlighting",),
            ("exfil_filter",),
        ]
        for names in configs:
            for scenario in scenarios:
                results.append(run(scenario, names, payload_id=None, rep=rep))
                for p in scenario.attacker.payload_ids:
                    results.append(run(scenario, names, payload_id=p, rep=rep))

    verdicts = classify(results)
    assert verdicts
    for v in verdicts:
        expected = v.reduction_pair - v.reduction_a - v.reduction_b
        assert abs(expected - v.synergy) < 1e-9
        if v.synergy > 0.01:
            assert v.verdict == "super-additive"
        elif v.synergy < -0.01:
            assert v.verdict == "redundant"
        else:
            assert v.verdict == "additive"


def test_baseline_cell_exists_for_classification():
    scenarios = [s for s in all_scenarios() if s.attacker is not None][:2]
    results = collect(scenarios, [()], reps=1)
    assert cell_for(results, "none") is not None
