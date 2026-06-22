"""Self-maturity scorecard — real per-dimension scores, NO fabricated competitor.

Honesty regression: the old build_strix_comparison_scorecard hardcoded every
Strix axis = 100 and emitted overall_strix / overall_gap into every scan's
retrospective — a fabricated competitor number presented as a comparison, and
the old test LOCKED IT IN. The rubric's per-dimension scores are computed from
real scan data and worth keeping; the fictional Strix baseline is not.
"""

from __future__ import annotations

from vxis.growth.maturity_scorecard import build_maturity_scorecard

_DIMS = {"poc_rigor", "chaining_depth", "campaign_convergence", "autonomy", "operator_visibility"}


def _scorecard():
    return build_maturity_scorecard(
        findings=[
            {
                "finding_type": "sql_injection",
                "severity": "critical",
                "title": "SQLI on q",
                "technical_analysis": "Control pair recorded.",
                "poc_description": "Replay payload and compare response.",
                "poc_script_code": "curl ...",
                "evidence": "GET /search?q=' ...",
            },
        ],
        loop_result={
            "completed": False,
            "verdict_counts": {"CONFIRMED": 1, "UNCONFIRMED": 0, "REFUTED": 0},
            "review_queue": [],
            "review_history": [{"stage": "verifier"}],
            "branches": [{"id": "b1", "status": "open"}],
        },
        attack_chains=[{"raw": {"crown_jewel": "authenticated data exfiltration"}}],
        llm_usage={"llm_calls": 4, "brain_decisions": 4},
        control_plane={"focus_branch": {"id": "web:sqli"}, "focus_campaign": {"family": "injection"}},
    )


def test_produces_real_dimension_scores():
    sc = _scorecard()
    assert set(sc["dimensions"]) == _DIMS
    assert all(0.0 <= sc["dimensions"][k] <= 100.0 for k in _DIMS)
    assert sc["overall"] > 0
    assert sc["method"] == "self_maturity_rubric_v1"


def test_no_fabricated_competitor_baseline():
    sc = _scorecard()
    # the whole fiction is gone: no 'strix' anywhere, no competitor/gap keys
    assert "strix" not in repr(sc).lower()
    for forbidden in ("reference", "overall_strix", "overall_gap"):
        assert forbidden not in sc
    # dimensions are bare floats now, not {vxis, strix, gap} triples
    for value in sc["dimensions"].values():
        assert isinstance(value, (int, float))
