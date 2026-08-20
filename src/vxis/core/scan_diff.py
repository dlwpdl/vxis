"""Scan comparison (diff) module for VXIS.

Compares two scans by matching findings on ``dedup_hash`` and classifying
each finding as *new*, *resolved*, *unknown*, *unchanged*, or *changed*
(severity shifted). Supports both DB-backed comparison (by scan ID) and
in-memory comparison of Finding lists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sqlalchemy import select

from vxis.core.db import create_engine, get_session
from vxis.models.db_models import FindingRecord, ScanRecord

if TYPE_CHECKING:
    from vxis.models.finding import Finding


@dataclass
class ChangedFinding:
    """A finding whose severity changed between two scans."""

    finding: "Finding"
    old_severity: str
    new_severity: str


@dataclass
class ScanDiffResult:
    """Structured result of comparing two scans.

    Attributes:
        new_findings: Findings present in scan B but not in scan A.
        resolved_findings: Findings absent from a complete, same-scope scan B.
        unknown_findings: Findings absent when scan B coverage is not comparable.
        unchanged_findings: Findings present in both with same severity.
        changed_findings: Findings present in both but with different severity.
    """

    new_findings: list["Finding"] = field(default_factory=list)
    resolved_findings: list["Finding"] = field(default_factory=list)
    unknown_findings: list["Finding"] = field(default_factory=list)
    unchanged_findings: list["Finding"] = field(default_factory=list)
    changed_findings: list[ChangedFinding] = field(default_factory=list)

    @property
    def total_a(self) -> int:
        """Total findings in scan A, including coverage-unknown findings."""
        return (
            len(self.resolved_findings)
            + len(self.unknown_findings)
            + len(self.unchanged_findings)
            + len(self.changed_findings)
        )

    @property
    def total_b(self) -> int:
        """Total findings in scan B (new + unchanged + changed)."""
        return len(self.new_findings) + len(self.unchanged_findings) + len(self.changed_findings)

    @property
    def summary(self) -> dict[str, int]:
        """Return a summary dict of counts for each category."""
        return {
            "new": len(self.new_findings),
            "resolved": len(self.resolved_findings),
            "unknown": len(self.unknown_findings),
            "unchanged": len(self.unchanged_findings),
            "changed": len(self.changed_findings),
            "total_a": self.total_a,
            "total_b": self.total_b,
        }


def compare_finding_lists(
    findings_a: list["Finding"],
    findings_b: list["Finding"],
    *,
    missing_is_resolved: bool = True,
) -> ScanDiffResult:
    """Compare two lists of Finding objects in memory.

    Matching is performed on ``dedup_hash``. For findings with matching hashes
    the effective severity is compared. Baseline-only findings are resolved by
    default, or unknown when ``missing_is_resolved`` is false.

    Args:
        findings_a: Findings from the baseline (older) scan.
        findings_b: Findings from the comparison (newer) scan.
        missing_is_resolved: Whether baseline-only findings count as resolved.

    Returns:
        A :class:`ScanDiffResult` with categorised findings.
    """
    map_a: dict[str, "Finding"] = {f.dedup_hash: f for f in findings_a}
    map_b: dict[str, "Finding"] = {f.dedup_hash: f for f in findings_b}

    hashes_a = set(map_a.keys())
    hashes_b = set(map_b.keys())

    new_findings: list["Finding"] = []
    resolved_findings: list["Finding"] = []
    unknown_findings: list["Finding"] = []
    unchanged_findings: list["Finding"] = []
    changed_findings: list[ChangedFinding] = []

    # New: in B but not in A
    for h in sorted(hashes_b - hashes_a):
        new_findings.append(map_b[h])

    # Missing from B is only resolved when B completed the same scan scope.
    for h in sorted(hashes_a - hashes_b):
        target = resolved_findings if missing_is_resolved else unknown_findings
        target.append(map_a[h])

    # Common: in both
    for h in sorted(hashes_a & hashes_b):
        fa = map_a[h]
        fb = map_b[h]
        if fa.effective_severity != fb.effective_severity:
            changed_findings.append(
                ChangedFinding(
                    finding=fb,
                    old_severity=fa.effective_severity.value,
                    new_severity=fb.effective_severity.value,
                )
            )
        else:
            unchanged_findings.append(fb)

    return ScanDiffResult(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unknown_findings=unknown_findings,
        unchanged_findings=unchanged_findings,
        changed_findings=changed_findings,
    )


async def compare_scans(
    scan_id_a: int,
    scan_id_b: int,
    db_url: str,
) -> ScanDiffResult:
    """Compare two scans stored in the database.

    Loads findings and scan metadata for both IDs, converts records to Pydantic
    :class:`Finding` models, and only treats missing findings as resolved when
    the newer scan completed the same target and profile.

    Args:
        scan_id_a: Primary key of the baseline (older) scan.
        scan_id_b: Primary key of the comparison (newer) scan.
        db_url: SQLAlchemy async database URL.

    Returns:
        A :class:`ScanDiffResult` with categorised findings.
    """
    from vxis.core.finding_records import convert_finding_records

    engine = create_engine(db_url)
    try:
        async with get_session(engine) as session:
            scan_a = await session.get(ScanRecord, scan_id_a)
            scan_b = await session.get(ScanRecord, scan_id_b)
            result_a = await session.execute(
                select(FindingRecord).where(FindingRecord.scan_id == scan_id_a)
            )
            records_a = list(result_a.scalars().all())

            result_b = await session.execute(
                select(FindingRecord).where(FindingRecord.scan_id == scan_id_b)
            )
            records_b = list(result_b.scalars().all())

        findings_a = convert_finding_records(records_a)
        findings_b = convert_finding_records(records_b)
        missing_is_resolved = bool(
            scan_a is not None
            and scan_b is not None
            and str(scan_b.status).lower() == "completed"
            and scan_a.target == scan_b.target
            and scan_a.profile == scan_b.profile
        )

        return compare_finding_lists(
            findings_a,
            findings_b,
            missing_is_resolved=missing_is_resolved,
        )
    finally:
        await engine.dispose()
