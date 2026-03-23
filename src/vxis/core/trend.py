"""Trend analysis module for VXIS.

Provides time-series trend data for individual targets and portfolio-wide
aggregates.  Each :class:`TrendPoint` captures severity counts and a
weighted risk score for a single scan, enabling dashboards and CLI
commands to visualise security posture over time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from vxis.core.db import create_engine, get_session
from vxis.models.db_models import FindingRecord, ScanRecord
from vxis.models.finding import Severity

if TYPE_CHECKING:
    pass

# Same weights used by ReportData.risk_score in vxis.report.generator
_SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.critical.value: 10.0,
    Severity.high.value: 7.0,
    Severity.medium.value: 4.0,
    Severity.low.value: 1.5,
    Severity.informational.value: 0.1,
}

_SEVERITY_ORDER: list[str] = [
    Severity.critical.value,
    Severity.high.value,
    Severity.medium.value,
    Severity.low.value,
    Severity.informational.value,
]


def _compute_risk_score(severity_counts: dict[str, int], total: int) -> float:
    """Compute risk score using the same formula as ReportData.

    Weighted sum normalised against the theoretical maximum (all findings
    are Critical), scaled to 0-10.

    Args:
        severity_counts: Mapping of severity level to count.
        total: Total number of findings.

    Returns:
        Risk score rounded to two decimal places, clamped to [0, 10].
    """
    if total == 0:
        return 0.0

    raw = sum(_SEVERITY_WEIGHTS.get(sev, 0.0) * count for sev, count in severity_counts.items())
    max_possible = _SEVERITY_WEIGHTS[Severity.critical.value] * total
    if max_possible == 0:
        return 0.0

    score = (raw / max_possible) * 10.0
    return round(min(score, 10.0), 2)


@dataclass
class TrendPoint:
    """A single data point in a security trend time-series.

    Attributes:
        scan_id: Primary key of the scan.
        target: Scan target identifier.
        date: Timestamp when the scan was started.
        severity_counts: Number of findings per severity level.
        total_findings: Total number of findings in this scan.
        risk_score: Weighted risk score (0-10 scale).
    """

    scan_id: int
    target: str
    date: datetime
    severity_counts: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    risk_score: float = 0.0


def _build_trend_point(scan: ScanRecord, findings: list[FindingRecord]) -> TrendPoint:
    """Build a TrendPoint from a ScanRecord and its associated findings."""
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f.effective_severity if f.effective_severity else f.severity
        counts[sev] = counts.get(sev, 0) + 1

    total = len(findings)
    risk = _compute_risk_score(counts, total)

    return TrendPoint(
        scan_id=scan.id,
        target=scan.target,
        date=scan.started_at,
        severity_counts=counts,
        total_findings=total,
        risk_score=risk,
    )


async def get_trend(
    target: str,
    db_url: str,
    limit: int = 30,
) -> list[TrendPoint]:
    """Return trend data for a specific target.

    Queries all completed scans for *target*, ordered by date ascending,
    limited to the most recent *limit* scans.  For each scan, aggregate
    severity counts from its findings and compute a risk score.

    Args:
        target: Target identifier to filter scans.
        db_url: SQLAlchemy async database URL.
        limit: Maximum number of trend points to return.

    Returns:
        List of :class:`TrendPoint` objects ordered chronologically.
    """
    engine = create_engine(db_url)
    try:
        async with get_session(engine) as session:
            stmt = (
                select(ScanRecord)
                .where(ScanRecord.target == target)
                .order_by(ScanRecord.started_at.asc())
                .limit(limit)
                .options(selectinload(ScanRecord.findings))
            )
            result = await session.execute(stmt)
            scans = list(result.scalars().all())

        points: list[TrendPoint] = []
        for scan in scans:
            points.append(_build_trend_point(scan, scan.findings))

        return points
    finally:
        await engine.dispose()


async def get_portfolio_trend(
    db_url: str,
    limit: int = 30,
) -> list[TrendPoint]:
    """Return trend data aggregated across all targets.

    Groups scans by their ``started_at`` date (most recent first), then
    aggregates severity counts from all findings in each scan into a
    single portfolio-level :class:`TrendPoint`.

    Args:
        db_url: SQLAlchemy async database URL.
        limit: Maximum number of scans to include.

    Returns:
        List of :class:`TrendPoint` objects ordered chronologically.
    """
    engine = create_engine(db_url)
    try:
        async with get_session(engine) as session:
            stmt = (
                select(ScanRecord)
                .order_by(ScanRecord.started_at.asc())
                .limit(limit)
                .options(selectinload(ScanRecord.findings))
            )
            result = await session.execute(stmt)
            scans = list(result.scalars().all())

        points: list[TrendPoint] = []
        for scan in scans:
            point = _build_trend_point(scan, scan.findings)
            point.target = "*"  # portfolio-wide marker
            points.append(point)

        return points
    finally:
        await engine.dispose()
