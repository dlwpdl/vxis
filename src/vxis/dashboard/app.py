"""VXIS web dashboard — FastAPI application.

Provides a server-side-rendered web UI for viewing scan results, filtering
findings, and exporting HTML reports. HTMX handles dynamic partial updates
without a JavaScript framework.
"""

from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload

from vxis.core.db import create_engine, get_session, init_db
from vxis.models.db_models import FindingRecord, ScanRecord
from vxis.report.charts import severity_bar_svg, severity_donut_svg

# ---------------------------------------------------------------------------
# Engine — uses the default VXIS database path; can be overridden in tests
# ---------------------------------------------------------------------------

_DEFAULT_DB_URL = "sqlite+aiosqlite:///vxis.db"

# Module-level engine; replaced in tests via app.state.engine
_engine = create_engine(_DEFAULT_DB_URL)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(application: FastAPI):  # type: ignore[no-untyped-def]
    """Initialise the DB schema on startup."""
    engine = getattr(application.state, "engine", _engine)
    await init_db(engine)
    yield


app = FastAPI(title="VXIS Dashboard", version="0.1.0", lifespan=_lifespan)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# Register chart helpers as Jinja2 globals
templates.env.globals["severity_donut_svg"] = severity_donut_svg
templates.env.globals["severity_bar_svg"] = severity_bar_svg

# Jinja2 filter: format datetime objects
def _fmt_dt(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.strftime(fmt)


templates.env.filters["fmtdt"] = _fmt_dt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_engine(request: Request):  # type: ignore[return]
    """Return the engine from app state (allows test overrides) or the default."""
    return getattr(request.app.state, "engine", _engine)


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

_SEVERITY_COLOURS: dict[str, str] = {
    "critical": "bg-red-900 text-red-100",
    "high": "bg-red-600 text-white",
    "medium": "bg-orange-500 text-white",
    "low": "bg-green-600 text-white",
    "informational": "bg-blue-500 text-white",
}

templates.env.globals["severity_colours"] = _SEVERITY_COLOURS
templates.env.globals["severity_order"] = _SEVERITY_ORDER


def _counts_from_findings(findings: list[FindingRecord]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        key = f.effective_severity.lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Dashboard home — list all scans with summary stats."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        # All scans ordered most-recent first
        result = await session.execute(
            select(ScanRecord).order_by(ScanRecord.started_at.desc())
        )
        scans: list[ScanRecord] = list(result.scalars().all())

        # Per-scan finding counts in one query
        counts_result = await session.execute(
            select(FindingRecord.scan_id, func.count(FindingRecord.id)).group_by(
                FindingRecord.scan_id
            )
        )
        finding_counts: dict[int, int] = {
            row[0]: row[1] for row in counts_result.all()
        }

        # Critical count across all scans
        crit_result = await session.execute(
            select(func.count(FindingRecord.id)).where(
                FindingRecord.effective_severity == "critical"
            )
        )
        total_critical: int = crit_result.scalar_one_or_none() or 0

    total_findings = sum(finding_counts.values())

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "scans": scans,
            "finding_counts": finding_counts,
            "total_scans": len(scans),
            "total_findings": total_findings,
            "total_critical": total_critical,
        },
    )


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str) -> HTMLResponse:
    """Scan detail page — charts, filters, and findings table."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        scan_result = await session.execute(
            select(ScanRecord).where(ScanRecord.id == int(scan_id))
        )
        scan: ScanRecord | None = scan_result.scalar_one_or_none()

        if scan is None:
            return templates.TemplateResponse(
                request,
                "404.html",
                {"message": f"Scan {scan_id} not found"},
                status_code=404,
            )

        findings_result = await session.execute(
            select(FindingRecord)
            .where(FindingRecord.scan_id == int(scan_id))
            .order_by(FindingRecord.effective_severity)
        )
        findings: list[FindingRecord] = list(findings_result.scalars().all())

    counts = _counts_from_findings(findings)

    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {
            "scan": scan,
            "findings": findings,
            "counts": counts,
            "scan_id": scan_id,
        },
    )


@app.get("/scan/{scan_id}/findings", response_class=HTMLResponse)
async def findings_partial(
    request: Request,
    scan_id: str,
    severity: str | None = Query(None),
    status: str | None = Query(None),
) -> HTMLResponse:
    """HTMX partial — filtered findings table rows."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        stmt = select(FindingRecord).where(FindingRecord.scan_id == int(scan_id))

        if severity and severity != "all":
            stmt = stmt.where(FindingRecord.effective_severity == severity.lower())
        if status and status != "all":
            stmt = stmt.where(FindingRecord.status == status.lower())

        # Sort by severity weight descending (critical first) using SQLAlchemy 2.x case()
        severity_order_case = case(
            (FindingRecord.effective_severity == "critical", 0),
            (FindingRecord.effective_severity == "high", 1),
            (FindingRecord.effective_severity == "medium", 2),
            (FindingRecord.effective_severity == "low", 3),
            (FindingRecord.effective_severity == "informational", 4),
            else_=5,
        )
        stmt = stmt.order_by(severity_order_case, FindingRecord.title)

        result = await session.execute(stmt)
        findings: list[FindingRecord] = list(result.scalars().all())

    return templates.TemplateResponse(
        request,
        "partials/findings_table.html",
        {
            "findings": findings,
            "scan_id": scan_id,
        },
    )


@app.get("/scan/{scan_id}/finding/{finding_id}", response_class=HTMLResponse)
async def finding_detail(
    request: Request, scan_id: str, finding_id: str
) -> HTMLResponse:
    """Finding detail page — full evidence, remediation, and metadata."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        scan_result = await session.execute(
            select(ScanRecord).where(ScanRecord.id == int(scan_id))
        )
        scan: ScanRecord | None = scan_result.scalar_one_or_none()

        finding_result = await session.execute(
            select(FindingRecord).where(
                FindingRecord.id == int(finding_id),
                FindingRecord.scan_id == int(scan_id),
            )
        )
        finding: FindingRecord | None = finding_result.scalar_one_or_none()

    if finding is None or scan is None:
        return templates.TemplateResponse(
            request,
            "404.html",
            {"message": "Finding not found"},
            status_code=404,
        )

    return templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "scan": scan,
            "finding": finding,
            "scan_id": scan_id,
        },
    )


@app.get("/scan/{scan_id}/export")
async def export_report(
    request: Request,
    scan_id: str,
    format: str = Query("html", description="Export format: html"),
) -> FileResponse:
    """Export a scan as a standalone HTML report file."""
    from datetime import date

    from vxis.models.finding import (
        CVSSVector,
        Evidence,
        Finding,
        FindingStatus,
        MitreAttack,
        Reference,
        Severity,
    )
    from vxis.report.generator import ReportData, ReportGenerator

    engine = _get_engine(request)

    async with get_session(engine) as session:
        scan_result = await session.execute(
            select(ScanRecord).where(ScanRecord.id == int(scan_id))
        )
        scan: ScanRecord | None = scan_result.scalar_one_or_none()

        if scan is None:
            return HTMLResponse(content="Scan not found", status_code=404)  # type: ignore[return-value]

        findings_result = await session.execute(
            select(FindingRecord).where(FindingRecord.scan_id == int(scan_id))
        )
        records: list[FindingRecord] = list(findings_result.scalars().all())

    # Convert FindingRecord ORM rows back to Pydantic Finding models
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

    report_data = ReportData(
        scan_id=str(scan_id),
        client_name=scan.target,
        target=scan.target,
        scan_date=scan.started_at.strftime("%Y-%m-%d") if scan.started_at else str(date.today()),
        findings=findings,
    )

    generator = ReportGenerator()
    html_content = generator.render_html(report_data)

    # Write to a temp file and return as download
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".html",
        delete=False,
        encoding="utf-8",
        prefix=f"vxis_report_{scan_id}_",
    )
    tmp.write(html_content)
    tmp.close()

    filename = f"vxis_report_{scan.target.replace('/', '_')}_{scan_id}.html"

    return FileResponse(
        path=tmp.name,
        media_type="text/html",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}
