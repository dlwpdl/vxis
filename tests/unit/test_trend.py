"""Tests for the trend analysis module."""

from __future__ import annotations

import pytest

from vxis.core.trend import TrendPoint, _compute_risk_score
from vxis.models.finding import Severity


class TestComputeRiskScore:
    """Tests for the _compute_risk_score helper."""

    def test_empty_findings(self) -> None:
        """Zero findings yields a risk score of 0.0."""
        score = _compute_risk_score({}, 0)
        assert score == 0.0

    def test_all_critical(self) -> None:
        """All-critical findings yield a risk score of 10.0."""
        counts = {"critical": 5, "high": 0, "medium": 0, "low": 0, "informational": 0}
        score = _compute_risk_score(counts, 5)
        assert score == 10.0

    def test_all_informational(self) -> None:
        """All-informational findings yield a very low risk score."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 10}
        score = _compute_risk_score(counts, 10)
        assert score == pytest.approx(0.1, abs=0.01)

    def test_mixed_severities(self) -> None:
        """Mixed severities produce a score between 0 and 10."""
        counts = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}
        total = 15
        score = _compute_risk_score(counts, total)
        assert 0.0 < score < 10.0

        # Manually verify: (10*1 + 7*2 + 4*3 + 1.5*4 + 0.1*5) = 10+14+12+6+0.5 = 42.5
        # max = 10 * 15 = 150
        # score = (42.5 / 150) * 10 = 2.8333...
        assert score == pytest.approx(2.83, abs=0.01)

    def test_all_high(self) -> None:
        """All-high findings yield a score of 7.0."""
        counts = {"critical": 0, "high": 3, "medium": 0, "low": 0, "informational": 0}
        score = _compute_risk_score(counts, 3)
        assert score == 7.0

    def test_all_medium(self) -> None:
        """All-medium findings yield a score of 4.0."""
        counts = {"critical": 0, "high": 0, "medium": 4, "low": 0, "informational": 0}
        score = _compute_risk_score(counts, 4)
        assert score == 4.0

    def test_all_low(self) -> None:
        """All-low findings yield a score of 1.5."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 2, "informational": 0}
        score = _compute_risk_score(counts, 2)
        assert score == 1.5

    def test_score_clamped_to_ten(self) -> None:
        """Score never exceeds 10.0 even with unusual inputs."""
        # Edge case: if weights were ever misconfigured
        counts = {"critical": 100}
        score = _compute_risk_score(counts, 100)
        assert score <= 10.0

    def test_single_critical(self) -> None:
        """A single critical finding produces a score of 10.0."""
        counts = {"critical": 1}
        score = _compute_risk_score(counts, 1)
        assert score == 10.0


class TestTrendPoint:
    """Tests for the TrendPoint dataclass."""

    def test_default_values(self) -> None:
        """TrendPoint defaults are sensible."""
        from datetime import datetime, timezone

        pt = TrendPoint(
            scan_id=1,
            target="10.0.0.1",
            date=datetime.now(timezone.utc),
        )
        assert pt.severity_counts == {}
        assert pt.total_findings == 0
        assert pt.risk_score == 0.0

    def test_populated_values(self) -> None:
        """TrendPoint stores provided values correctly."""
        from datetime import datetime, timezone

        counts = {"critical": 2, "high": 3}
        pt = TrendPoint(
            scan_id=42,
            target="example.com",
            date=datetime(2025, 1, 15, tzinfo=timezone.utc),
            severity_counts=counts,
            total_findings=5,
            risk_score=8.14,
        )
        assert pt.scan_id == 42
        assert pt.target == "example.com"
        assert pt.severity_counts["critical"] == 2
        assert pt.total_findings == 5
        assert pt.risk_score == 8.14
