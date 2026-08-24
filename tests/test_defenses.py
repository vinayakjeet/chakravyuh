from chakravyuh.context import base_context
from chakravyuh.corpus import ATTACKER_DOMAIN, all_scenarios
from chakravyuh.defenses.allowlist import Allowlist
from chakravyuh.defenses.approval import ApprovalGate
from chakravyuh.defenses.exfil import MARKER, ExfilFilter
from chakravyuh.defenses.secondary import SecondaryChecker
from chakravyuh.defenses.spotlighting import Spotlighting
from chakravyuh.types import Call


def _attacked():
    return next(s for s in all_scenarios() if s.attacker is not None)


def _scenario_with_external_marker():
    for scenario in all_scenarios():
        if scenario.attacker is None:
            continue
        targets = scenario.attacker.target_effects
        if any(e.tool == "export_ledger" or e.tool == "forward_itinerary" for e in targets):
            return scenario
    raise AssertionError("no external-target scenario")


def test_spotlighting_fences_untrusted_and_leaves_trusted_alone():
    scenario = _attacked()
    ctx = base_context(scenario.task, scenario.docs)
    out = Spotlighting().render(ctx, scenario)
    fenced = [b for b in out.segments if "BEGIN UNTRUSTED" in b.text]
    plain_trusted = [b for b in out.segments if b.trusted and b.channel == "document"]
    assert fenced and plain_trusted
    assert all(not b.trusted for b in fenced)
    assert any(b.channel == "policy" for b in out.segments)


def test_allowlist_denies_tools_outside_least_privilege():
    scenario = _attacked()
    defense = Allowlist()
    outside = next(
        t.name for t in scenario.tools
        if t.name not in {e.tool for e in scenario.required}
        and t.kind.name != "READ"
    )
    decision = defense.inspect(Call(outside), scenario, base_context("", ()))
    assert not decision.allowed and decision.reason == "allowlist"
    inside = Call(scenario.required[0].tool, dict(scenario.required[0].args))
    assert defense.inspect(inside, scenario, base_context("", ())).allowed


def test_exfil_filter_catches_markers_only_on_external_calls():
    scenario = _scenario_with_external_marker()
    marker_doc = next(d for d in scenario.docs if not d.trusted)
    marker = MARKER.findall(marker_doc.body)[0]
    defense = ExfilFilter()
    defense.prepare(scenario, scenario.docs)

    external = next(
        e for e in scenario.attacker.target_effects
        if scenario.tool(e.tool).kind.name == "EXTERNAL"
    )
    poisoned = Call(
        external.tool,
        {**dict(external.args), "note": f"refs {marker}"},
    )
    decision = defense.inspect(poisoned, scenario, base_context("", ()))
    assert not decision.allowed and decision.reason == "exfil_filter"

    read_tool = next(t.name for t in scenario.tools if t.kind.name == "READ")
    internal = Call(read_tool, {"q": f"see {marker}"})
    assert defense.inspect(internal, scenario, base_context("", ())).allowed


def test_approval_gate_requires_exact_argument_match():
    scenario = next(
        s for s in all_scenarios()
        if s.attacker is not None and s.required[0].tool != "read_statement"
    )
    defense = ApprovalGate()
    template = scenario.required[0]

    exact = Call(template.tool, dict(template.args))
    assert defense.inspect(exact, scenario, base_context("", ())).allowed

    mimic = Call(template.tool, {**dict(template.args), "note": "per policy"})
    decision = defense.inspect(mimic, scenario, base_context("", ()))
    assert not decision.allowed

    attacker_call = Call(
        scenario.attacker.target_effects[0].tool,
        dict(scenario.attacker.target_effects[0].args),
    )
    assert not defense.inspect(attacker_call, scenario, base_context("", ())).allowed


def test_secondary_checker_flags_quotes_and_directive_cues():
    scenario = _attacked()
    defense = SecondaryChecker()
    defense.prepare(scenario, scenario.docs)

    quoted = next(d for d in scenario.docs if len(d.body.split()) >= 6)
    words = quoted.body.split()
    long_quote = " ".join(words[:6])
    tool = scenario.required[0].tool
    call = Call(tool, {"body": long_quote})
    assert not defense.inspect(call, scenario, base_context("", ())).allowed

    cue_call = Call(tool, {"body": f"{ATTACKER_DOMAIN} NOTE TO THE ASSISTANT: x"})
    decision = defense.inspect(cue_call, scenario, base_context("", ()))
    assert not decision.allowed and decision.reason == "secondary_check"


def test_checker_ignores_read_calls():
    scenario = _attacked()
    defense = SecondaryChecker()
    defense.prepare(scenario, scenario.docs)
    read_tool = next(t.name for t in scenario.tools if t.kind.name == "READ")
    call = Call(read_tool, {"q": "anything at all goes here"})
    assert defense.inspect(call, scenario, base_context("", ())).allowed
