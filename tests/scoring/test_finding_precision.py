"""ADR-008 Finding Precision scoring tests.

Before the fix: `total_judged == 0` returned 140pts (perverse — 판정 안 할수록
고득점), and `total_judged == 1` could swing the full dim between 0~200pts.

After the fix: Bayesian smoothing with α=β=3 keeps sub-threshold samples close
to the neutral prior (100pts), only releasing full weight at n >= 3.
"""
from __future__ import annotations

import pytest

from vxis.scoring.engine import (
    _MIN_JUDGMENTS_FOR_CONFIDENCE,
    _PRECISION_PRIOR,
    ScoringEngine,
)
from vxis.scoring.tracker import ScoreTracker


def _make_tracker(tp: int, fp: int, findings_count: int) -> ScoreTracker:
    tracker = ScoreTracker(target_type="web")
    for i in range(findings_count):
        tracker.exploitation_levels[f"F{i}"] = 1
    for i in range(tp):
        tracker.analyst_verdicts[f"TP{i}"] = True
    for i in range(fp):
        tracker.analyst_verdicts[f"FP{i}"] = False
    return tracker


@pytest.fixture()
def engine() -> ScoringEngine:
    return ScoringEngine("web")


class TestNoJudgmentNeutral:
    """ADR-008: `total_judged == 0` → 100pts (neutral), not 140pts."""

    def test_findings_present_no_judgment_returns_100(self, engine):
        tracker = _make_tracker(tp=0, fp=0, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        assert dim.score == pytest.approx(100.0)
        assert dim.details["measurement_valid"] is False
        assert dim.details["total_judged"] == 0

    def test_no_findings_returns_zero(self, engine):
        tracker = _make_tracker(tp=0, fp=0, findings_count=0)
        dim = engine._calc_finding_precision(tracker, [])
        assert dim.score == pytest.approx(0.0)
        assert dim.details["measurement_valid"] is False


class TestBayesianSmoothing:
    """ADR-008: `1 <= total_judged < 3` → (tp+α)/(n+2α) × 200."""

    def test_single_fp_judgment_is_smoothed_not_zero(self, engine):
        tracker = _make_tracker(tp=0, fp=1, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        expected = (0 + _PRECISION_PRIOR) / (1 + 2 * _PRECISION_PRIOR) * 200.0
        assert dim.score == pytest.approx(expected)
        assert dim.details["measurement_valid"] is False

    def test_single_tp_judgment_is_smoothed_not_200(self, engine):
        tracker = _make_tracker(tp=1, fp=0, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        expected = (1 + _PRECISION_PRIOR) / (1 + 2 * _PRECISION_PRIOR) * 200.0
        assert dim.score == pytest.approx(expected)
        assert dim.details["measurement_valid"] is False

    def test_two_judgments_still_smoothed(self, engine):
        tracker = _make_tracker(tp=1, fp=1, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        expected = (1 + _PRECISION_PRIOR) / (2 + 2 * _PRECISION_PRIOR) * 200.0
        assert dim.score == pytest.approx(expected)
        assert dim.details["measurement_valid"] is False

    def test_noise_delta_under_fifteen_percent(self, engine):
        """baseline(j=0) vs after(j=1, FP=1) must now differ by ≤15pts.

        Before fix the same pair differed by 140pts. This is the core
        regression the ADR-008 fix is designed to kill — tight bound here
        prevents future scoring tweaks from re-introducing the noise.
        """
        base = engine._calc_finding_precision(_make_tracker(0, 0, 22), []).score
        after = engine._calc_finding_precision(_make_tracker(0, 1, 22), []).score
        assert abs(base - after) <= 15.0


class TestThresholdUnsmoothed:
    """ADR-008: `total_judged >= 3` → tp/n × 200 (unchanged)."""

    def test_threshold_exact_uses_raw_ratio(self, engine):
        tracker = _make_tracker(tp=2, fp=1, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        assert dim.score == pytest.approx(2 / 3 * 200.0)
        assert dim.details["measurement_valid"] is True

    def test_all_fp_at_scale_scores_zero(self, engine):
        tracker = _make_tracker(tp=0, fp=10, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        assert dim.score == pytest.approx(0.0)
        assert dim.details["measurement_valid"] is True

    def test_perfect_precision_at_scale_scores_200(self, engine):
        tracker = _make_tracker(tp=10, fp=0, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        assert dim.score == pytest.approx(200.0)
        assert dim.details["measurement_valid"] is True


class TestDetailsContract:
    def test_details_expose_adr008_flags(self, engine):
        tracker = _make_tracker(tp=0, fp=0, findings_count=22)
        dim = engine._calc_finding_precision(tracker, [])
        assert "measurement_valid" in dim.details
        assert dim.details["min_judgments_required"] == _MIN_JUDGMENTS_FOR_CONFIDENCE
