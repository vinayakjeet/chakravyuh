"""Prove the conventions checker catches each rule, by breaking it.

Exempt from its own scan for the same reason the checker is: a test that
carries live-looking strings must never be scanned by the thing it tests.
"""


from scripts.check_conventions import scan_lines


def _scan(text: str):
    return scan_lines(text.splitlines())


def test_em_dash_fails():
    failures, warnings = _scan("a bad claim - no wait, an em dash: x - y")
    assert not failures
    failures, _ = _scan("bad \u2014 dash")
    assert failures and "em or en dash" in failures[0]


def test_en_dash_fails():
    failures, _ = _scan("pages 3\u20137 are missing")
    assert failures


def test_attribution_fails():
    failures, _ = _scan("co-authored-by someone")
    assert any("attribution" in f for f in failures)


def test_credential_shape_fails_but_env_name_passes():
    failures, _ = _scan("GROQ_API_KEY=gsk_" + "A" * 20)
    assert any("credential" in f for f in failures)
    failures, _ = _scan("GROQ_API_KEY from env")
    assert not failures


def test_absolute_claims_warn_but_do_not_fail():
    failures, warnings = _scan("this gateway blocks prompt injection")
    assert not failures
    assert any("blocks" in w for w in warnings)


def test_plain_lines_are_clean():
    failures, _ = _scan("reduced ASR from 0.31 to 0.02 under this threat model.")
    assert not failures
