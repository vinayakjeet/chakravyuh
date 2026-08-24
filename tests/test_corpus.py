from chakravyuh.attacks import AttackKind, payload_kind
from chakravyuh.corpus import all_scenarios, suites
from chakravyuh.defenses.allowlist import least_privilege
from chakravyuh.types import ToolKind


def _attacked():
    return [s for s in all_scenarios() if s.attacker is not None]


def test_scenario_ids_unique():
    ids = [s.id for s in all_scenarios()]
    assert len(ids) == len(set(ids))


def test_three_suites_present():
    suites_now = suites()
    assert set(suites_now) == {"ledger", "mailbox", "trips"}
    for name, rows in suites_now.items():
        assert len(rows) >= 5, name


def test_required_effects_use_declared_tools():
    for scenario in all_scenarios():
        declared = {t.name for t in scenario.tools}
        assert {e.tool for e in scenario.required} <= declared
        if scenario.attacker is not None:
            assert {e.tool for e in scenario.attacker.target_effects} <= declared


def test_attacked_scenarios_have_all_three_routes_and_drip_pair():
    for scenario in _attacked():
        kinds = {payload_kind(p) for p in scenario.attacker.payload_ids}
        assert kinds == {
            AttackKind.IN_BAND, AttackKind.ADI_DATA, AttackKind.DRIP,
        }, scenario.id
        untrusted = [d for d in scenario.docs if not d.trusted]
        assert len(untrusted) >= 2, f"{scenario.id} needs a second doc for drip"


def test_benign_scenarios_exist_in_every_suite():
    for name, rows in suites().items():
        clean = [s for s in rows if s.attacker is None]
        assert clean, f"{name} has no benign-only scenarios"


def test_markers_unique_per_scenario_and_only_in_untrusted_docs():
    import re

    pattern = re.compile(r"REF-[A-Z0-9-]+")
    for scenario in all_scenarios():
        trusted_text = " ".join(d.body for d in scenario.docs if d.trusted)
        assert not pattern.search(trusted_text), scenario.id
        markers = []
        for doc in scenario.docs:
            if not doc.trusted:
                markers.extend(pattern.findall(doc.body))
        assert len(markers) == len(set(markers)), scenario.id
        if scenario.attacker is not None:
            assert markers, f"{scenario.id} needs markers for the exfil filter"


def test_least_privilege_covers_the_plan_and_reads():
    for scenario in all_scenarios():
        lp = least_privilege(scenario)
        reads = {t.name for t in scenario.tools if t.kind is ToolKind.READ}
        assert lp == {e.tool for e in scenario.required} | reads


def test_attacker_goals_differ_from_the_plan():
    attacked = 0
    for scenario in all_scenarios():
        if scenario.attacker is None:
            continue
        attacked += 1
        plan = {(e.tool, tuple(sorted(e.args.items()))) for e in scenario.required}
        goal = {(e.tool, tuple(sorted(e.args.items())))
                for e in scenario.attacker.target_effects}
        assert plan.isdisjoint(goal), scenario.id
    assert attacked == 12
