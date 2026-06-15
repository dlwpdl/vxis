"""NOW-1 review fix F2 — drift-tolerant verdict parsing.

The verifier verdict was only recognized when a line literally started with
"VERDICT:"; markdown bold, blockquote, em-dash, or inline phrasing fell through
to the UNCONFIRMED default — which under NOW-1/1.3 is now a hard report
exclusion, silently dropping genuinely-CONFIRMED findings on LLM formatting drift.
"""
import pytest

from vxis.agent.tools.verifier_tools import _extract_verdict


@pytest.mark.parametrize(
    "text,expected",
    [
        ("VERDICT: CONFIRMED", "CONFIRMED"),
        ("verdict: confirmed", "CONFIRMED"),
        ("**VERDICT:** CONFIRMED", "CONFIRMED"),
        ("> VERDICT: CONFIRMED", "CONFIRMED"),
        ("Verdict — CONFIRMED", "CONFIRMED"),  # em dash
        ("VERDICT - REFUTED", "REFUTED"),
        ("blah\n**VERDICT:** UNCONFIRMED\nCONFIDENCE: low", "UNCONFIRMED"),
        ("reasoning first\nVERDICT:REFUTED", "REFUTED"),
        ("no verdict token at all here", "UNCONFIRMED"),  # safe default
        ("", "UNCONFIRMED"),
    ],
)
def test_extract_verdict_tolerates_formatting_drift(text, expected):
    assert _extract_verdict(text) == expected
