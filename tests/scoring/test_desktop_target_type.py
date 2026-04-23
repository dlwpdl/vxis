"""Phase Q5 — ScoringEngine must accept target_type='desktop'.

Before this fix, scoring/engine.py:163 validated against
("web","game","mobile") only. Calling ScoringEngine(target_type="desktop")
raised ValueError, so _compute_vxis_score caught the exception and silently
fell back to web scoring — producing "[SCORE] WEB" log lines on desktop
scans (observed in phase-Q3 smoke).
"""
from __future__ import annotations

import pytest

from vxis.scoring.engine import ScoringEngine
from vxis.scoring.tracker import ScoreTracker
from vxis.scoring.vectors import DESKTOP_VECTORS


def test_scoring_engine_accepts_desktop() -> None:
    engine = ScoringEngine(target_type="desktop")
    assert engine.target_type == "desktop"
    assert engine._total_vectors == len(DESKTOP_VECTORS)


def test_scoring_engine_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="desktop"):
        ScoringEngine(target_type="alien")


def test_desktop_score_calculates_without_crash() -> None:
    engine = ScoringEngine(target_type="desktop")
    tracker = ScoreTracker(target_type="desktop")
    # Mark a couple of DESK-* vectors as attempted + found.
    tracker.vectors_attempted.update({"DESK-DYL-002", "DESK-SIG-004"})
    tracker.vectors_found.add("DESK-DYL-002")
    score = engine.calculate(tracker, findings=[], scan_id="phase-q5-test")
    assert score.target_type == "desktop"
    # Vector coverage should reflect the DESKTOP pool, not the WEB pool.
    assert score.vector_coverage.score > 0
