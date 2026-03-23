"""Delta report — compare two scans of the same target.

Computes the difference between the current scan's findings and the most
recent previous scan for the same target, categorising findings as new,
resolved, or persistent based on their dedup_hash.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vxis.models.finding import Finding


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class DeltaResult:
    """Comparison result between two scans of the same target.

    Attributes:
        target: The scan target (hostname, IP, etc.).
        current_scan_id: Scan ID for the newer scan.
        previous_scan_id: Scan ID for the older comparison scan.
        new_findings: Findings present in current but absent in previous.
        resolved_findings: Findings present in previous but absent in current.
        persistent_findings: Findings present in both scans.
    """

    target: str
    current_scan_id: str
    previous_scan_id: str
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    persistent_findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------


def compute_delta(
    current_findings: list[Finding],
    previous_findings: list[Finding],
    target: str = "",
    current_scan_id: str = "",
    previous_scan_id: str = "",
) -> DeltaResult:
    """Compare two finding lists and return a categorised DeltaResult.

    Findings are compared by their ``dedup_hash`` computed field.  The three
    possible categories are:

    * **new** — hash present in ``current_findings`` but not in
      ``previous_findings``.
    * **resolved** — hash present in ``previous_findings`` but not in
      ``current_findings``.
    * **persistent** — hash present in both.

    Args:
        current_findings: Findings from the newer scan.
        previous_findings: Findings from the older reference scan.
        target: Scan target label (used for display only).
        current_scan_id: Identifier of the current scan.
        previous_scan_id: Identifier of the previous scan.

    Returns:
        A :class:`DeltaResult` with findings categorised into three lists.
    """
    current_by_hash: dict[str, Finding] = {f.dedup_hash: f for f in current_findings}
    previous_by_hash: dict[str, Finding] = {f.dedup_hash: f for f in previous_findings}

    current_hashes = set(current_by_hash)
    previous_hashes = set(previous_by_hash)

    new_hashes = current_hashes - previous_hashes
    resolved_hashes = previous_hashes - current_hashes
    persistent_hashes = current_hashes & previous_hashes

    return DeltaResult(
        target=target,
        current_scan_id=current_scan_id,
        previous_scan_id=previous_scan_id,
        new_findings=[current_by_hash[h] for h in new_hashes],
        resolved_findings=[previous_by_hash[h] for h in resolved_hashes],
        persistent_findings=[current_by_hash[h] for h in persistent_hashes],
    )


# ---------------------------------------------------------------------------
# Display formatter
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def _summarise_findings(findings: list[Finding], max_items: int = 3) -> str:
    """Return a compact comma-separated summary of the top findings by severity."""
    if not findings:
        return ""

    def _sort_key(f: Finding) -> int:
        try:
            return _SEVERITY_ORDER.index(f.effective_severity.value)
        except (ValueError, AttributeError):
            return len(_SEVERITY_ORDER)

    sorted_findings = sorted(findings, key=_sort_key)
    parts = [
        f"{f.title} ({f.effective_severity.value})"
        for f in sorted_findings[:max_items]
    ]
    if len(findings) > max_items:
        parts.append(f"+{len(findings) - max_items}건 더")
    return ", ".join(parts)


def format_delta_summary(delta: DeltaResult) -> str:
    """Return a Rich-formatted summary string for CLI display.

    Example output::

        Delta Report: target.com
          신규 2건: SQL Injection (high), Open Redirect (medium)
          해결 1건: Weak TLS (medium)
          유지 5건

    Args:
        delta: A :class:`DeltaResult` produced by :func:`compute_delta`.

    Returns:
        A multi-line string with Rich markup ready for ``console.print()``.
    """
    lines: list[str] = []
    lines.append(f"[bold cyan]Delta Report:[/bold cyan] [white]{delta.target}[/white]")

    new_count = len(delta.new_findings)
    resolved_count = len(delta.resolved_findings)
    persistent_count = len(delta.persistent_findings)

    if new_count > 0:
        summary = _summarise_findings(delta.new_findings)
        lines.append(f"  [bold red]\U0001f195 신규 {new_count}건:[/bold red] {summary}")
    else:
        lines.append("  [dim]\U0001f195 신규 0건[/dim]")

    if resolved_count > 0:
        summary = _summarise_findings(delta.resolved_findings)
        lines.append(f"  [bold green]\u2705 해결 {resolved_count}건:[/bold green] {summary}")
    else:
        lines.append("  [dim]\u2705 해결 0건[/dim]")

    if persistent_count > 0:
        lines.append(f"  [yellow]\u27a1\ufe0f 유지 {persistent_count}건[/yellow]")
    else:
        lines.append("  [dim]\u27a1\ufe0f 유지 0건[/dim]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Database query helper
# ---------------------------------------------------------------------------


async def get_previous_scan_findings(
    engine: object,
    target: str,
    current_scan_id: str,
) -> tuple[list[Finding], str]:
    """Query the database for the most recent completed scan before ``current_scan_id``.

    Searches for the most recent scan record with ``status='completed'`` for
    the same ``target``, excluding the current scan.  Converts the persisted
    :class:`~vxis.models.db_models.FindingRecord` rows back into
    :class:`~vxis.models.finding.Finding` Pydantic models.

    Args:
        engine: An :class:`~sqlalchemy.ext.asyncio.AsyncEngine` instance.
        target: The scan target to match.
        current_scan_id: ID of the current scan (excluded from the search).

    Returns:
        A ``(findings, previous_scan_id)`` tuple.  ``findings`` is an empty
        list and ``previous_scan_id`` is ``""`` when no previous scan exists.
    """
    from sqlalchemy import select

    from vxis.core.db import get_session
    from vxis.models.db_models import FindingRecord, ScanRecord
    from vxis.models.finding import (
        CVSSVector,
        Evidence,
        Finding,
        FindingStatus,
        MitreAttack,
        Reference,
        Severity,
    )

    try:
        current_id_int = int(current_scan_id)
    except (ValueError, TypeError):
        return [], ""

    async with get_session(engine) as session:  # type: ignore[arg-type]
        # Find the most recent completed scan for the same target, before this one
        prev_stmt = (
            select(ScanRecord)
            .where(ScanRecord.target == target)
            .where(ScanRecord.status == "completed")
            .where(ScanRecord.id != current_id_int)
            .where(ScanRecord.id < current_id_int)
            .order_by(ScanRecord.id.desc())
            .limit(1)
        )
        prev_result = await session.execute(prev_stmt)
        prev_scan: ScanRecord | None = prev_result.scalar_one_or_none()

        if prev_scan is None:
            return [], ""

        findings_result = await session.execute(
            select(FindingRecord).where(FindingRecord.scan_id == prev_scan.id)
        )
        records: list[FindingRecord] = list(findings_result.scalars().all())

    findings: list[Finding] = []
    for rec in records:
        cvss = None
        if rec.cvss_score is not None and rec.cvss_vector:
            cvss = CVSSVector(vector_string=rec.cvss_vector, base_score=rec.cvss_score)

        mitre = None
        if rec.mitre_attack:
            mitre = MitreAttack(**rec.mitre_attack)

        evidence = [Evidence(**e) for e in (rec.evidence or [])]
        references = [Reference(**r) for r in (rec.references or [])]

        findings.append(
            Finding(
                id=str(rec.id),
                scan_id=str(rec.scan_id),
                title=rec.title,
                description=rec.description,
                severity=Severity(rec.severity),
                status=FindingStatus(rec.status),
                target=rec.target,
                affected_component=rec.affected_component or "",
                port=rec.port,
                protocol=rec.protocol,
                finding_type=rec.finding_type,
                cvss=cvss,
                cve_ids=rec.cve_ids or [],
                cwe_ids=rec.cwe_ids or [],
                mitre_attack=mitre,
                source_plugin=rec.source_plugin,
                source_plugins=rec.source_plugins or [],
                confidence=rec.confidence,
                evidence=evidence,
                remediation=rec.remediation,
                references=references,
                analyst_severity=Severity(rec.analyst_severity)
                if rec.analyst_severity
                else None,
                analyst_notes=rec.analyst_notes,
                discovered_at=rec.discovered_at,
                updated_at=rec.updated_at,
            )
        )

    return findings, str(prev_scan.id)
