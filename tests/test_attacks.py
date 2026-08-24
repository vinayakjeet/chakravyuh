from chakravyuh.attacks import (
    ADI_CUE,
    CODEWORD,
    DRIP_A_CUE,
    ECHO_PROBE_CUE,
    IN_BAND_CUE,
    AttackKind,
    directive_text,
    export_rows,
    inject,
    payload_kind,
)
from chakravyuh.corpus import all_scenarios


def _attacked():
    return next(s for s in all_scenarios() if s.attacker is not None)


def test_in_band_lands_in_the_primary_untrusted_doc():
    scenario = _attacked()
    out = inject(scenario, "inband-" + scenario.id)
    primary = next(d for d in out if not d.trusted)
    others = [d for d in out if d.id != primary.id]
    assert IN_BAND_CUE in primary.body
    assert all(IN_BAND_CUE not in d.body for d in others)


def test_adi_smuggles_a_directive_between_forged_field_delimiters():
    scenario = _attacked()
    out = inject(scenario, "adi-" + scenario.id)
    primary = next(d for d in out if not d.trusted)
    assert ADI_CUE in primary.body
    assert "<<<FIELD_END>>>" in primary.body
    assert "<<<FIELD_BEGIN>>>" in primary.body
    # the smuggled directive sits inside what a form parser reads as one value
    value_line = [ln for ln in primary.body.splitlines() if ln.startswith("value:")]
    assert value_line


def test_drip_splits_across_two_documents():
    scenario = _attacked()
    out = inject(scenario, "drip-" + scenario.id)
    untrusted = [d for d in out if not d.trusted]
    with_a = [d for d in untrusted if DRIP_A_CUE in d.body]
    with_b = [d for d in untrusted if f"{CODEWORD}: " in d.body]
    assert len(with_a) == 1 and len(with_b) == 1
    assert with_a[0].id != with_b[0].id


def test_base_injection_carries_no_probe():
    scenario = _attacked()
    probed = inject(scenario, "adi-" + scenario.id)
    assert ECHO_PROBE_CUE not in "".join(d.body for d in probed)


def test_directive_text_names_every_target_destination():
    for scenario in all_scenarios():
        if scenario.attacker is None:
            continue
        text = directive_text(scenario.attacker)
        for effect in scenario.attacker.target_effects:
            if "to" in effect.args:
                assert effect.args["to"] in text, scenario.id
            if effect.tool == "add_beneficiary":
                assert effect.args["account"] in text, scenario.id


def test_export_rows_carry_kind_and_targets():
    rows = export_rows(all_scenarios())
    attacked = [r for r in rows if r["payload"] is not None]
    expected = sum(
        len(s.attacker.payload_ids) for s in all_scenarios() if s.attacker is not None
    )
    assert len(attacked) == expected
    kinds = {r["kind"] for r in attacked}
    assert kinds == {k.value for k in AttackKind}


def test_unknown_payload_id_rejected():
    try:
        payload_kind("mystery-1")
    except ValueError:
        return
    raise AssertionError("unknown payload accepted")
