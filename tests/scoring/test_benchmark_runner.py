from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vxis.scoring.benchmark import BenchmarkRunner
from vxis.scoring.engine import DimensionScore, ScoringEngine, VXISScore
from vxis.scoring.reporter import ScoreComparison
from vxis.scoring.tracker import ScoreTracker


def _dim(name: str, score: float, max_score: float) -> DimensionScore:
    return DimensionScore(
        name=name,
        name_ko=name,
        score=score,
        max_score=max_score,
        percentage=score / max_score if max_score else 0.0,
        details={},
    )


def _score(total: float = 321.0) -> VXISScore:
    return VXISScore(
        total=total,
        grade="C",
        target_type="web",
        scan_id="scan-score-detail",
        timestamp="2026-04-28T00:00:00+00:00",
        vector_coverage=_dim("Vector Coverage", 50.0, 250.0),
        exploitation_reach=_dim("Exploitation Reach", 90.0, 300.0),
        chain_intelligence=_dim("Chain Intelligence", 40.0, 150.0),
        finding_precision=_dim("Finding Precision", 100.0, 200.0),
        completeness=_dim("Completeness", 41.0, 100.0),
    )


@pytest.mark.asyncio
async def test_run_benchmark_uses_pipeline_score_detail(tmp_path: Path, monkeypatch) -> None:
    """Growth loop must compare the same 5D score the pipeline printed.

    Brain-first ScanPipelineV2 populates ctx.score_detail via _compute_vxis_score().
    The legacy ScoreTracker on ctx can be sparse, so BenchmarkRunner must prefer
    score_detail when present instead of recalculating from an empty tracker.
    """
    expected = _score(total=321.0)
    ctx = SimpleNamespace(
        score_detail=expected,
        score_tracker=ScoreTracker(target_type="web"),
        findings=[],
    )

    async def fake_execute_pipeline(self, target_type: str, target_url: str, scan_id: str):
        return ctx

    monkeypatch.setattr(BenchmarkRunner, "_execute_pipeline", fake_execute_pipeline)

    runner = BenchmarkRunner(str(tmp_path / "baseline.json"))
    actual = await runner.run_benchmark("web", "http://localhost:3000")

    assert actual is expected
    assert actual.total == 321.0


def test_vector_coverage_details_preserve_vector_ids() -> None:
    base_tracker = ScoreTracker(target_type="web")
    base_tracker.record_vector_attempt("WEB-SQLI-001")

    current_tracker = ScoreTracker(target_type="web")
    current_tracker.record_vector_attempt("WEB-SQLI-001")
    current_tracker.record_vector_attempt("WEB-XSS-001")

    engine = ScoringEngine("web")
    baseline = engine.calculate(base_tracker, [], scan_id="base")
    current = engine.calculate(current_tracker, [], scan_id="current")
    comparison = ScoreComparison.build(baseline, current)

    assert "WEB-SQLI-001" in baseline.vector_coverage.details["vectors_attempted_ids"]
    assert "WEB-XSS-001" in comparison.new_vectors_covered
