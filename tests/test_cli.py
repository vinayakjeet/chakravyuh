import json

from typer.testing import CliRunner

from chakravyuh.__main__ import app
from chakravyuh.bench import run_all
from chakravyuh.corpus import all_scenarios
from chakravyuh.report import adaptive_table, interaction_table, matrix_table

runner = CliRunner()


def test_matrix_command_writes_tables(tmp_path):
    out = tmp_path / "matrix.md"
    result = runner.invoke(app, ["matrix", "--reps", "1", "--out", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "Benign utility" in text
    assert "ASR" in text
    assert "Adaptive attacks" in text


def test_status_json_has_the_keys_the_site_needs():
    report = run_all(reps=1)
    payload = {
        **report.headline,
        "generated": "2026-08-24",
        "source": "scripts/status.py",
    }
    for key in (
        "victim", "asr_no_defense", "best_config", "asr_best",
        "benign_utility_best", "reps", "defense_configs",
        "victim_susceptibility_dated",
    ):
        assert key in payload, key
    json.dumps(payload)


def test_report_renderers_do_not_move_numbers():
    from chakravyuh.runner import run
    from chakravyuh.scoring import cell_for

    results = []
    scenario = next(s for s in all_scenarios() if s.attacker is not None)
    for rep in range(2):
        results.append(run(scenario, (), payload_id=None, rep=rep))
        results.append(run(scenario, (), payload_id="inband-" + scenario.id, rep=rep))
    cell = cell_for(results, "none")
    table = matrix_table([("none", cell)], "t")
    assert f"{cell.asr:.3f}" in table


def test_interaction_and_adaptive_renderers_run():
    from chakravyuh.adaptive import AdaptiveRow
    from chakravyuh.interaction import PairVerdict

    v = PairVerdict("a + b", 0.1, 0.1, 0.05, 0.2, 0.2, 0.25, -0.15, "redundant")
    text = interaction_table([v])
    assert "redundant" in text
    row = AdaptiveRow("t", "l", "c", 10, 0.02, True)
    assert adaptive_table([row])


def test_export_corpus_writes_jsonl_with_hash(tmp_path):
    out = tmp_path / "corpus.jsonl"
    result = runner.invoke(app, ["export-corpus", "--out", str(out)])
    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) > 20
    parsed = json.loads(lines[0])
    assert {"scenario", "payload", "kind"} <= set(parsed)
    assert "sha256" in result.output
