"""VXIS web dashboard — FastAPI application.

Provides a server-side-rendered web UI for viewing scan results, filtering
findings, and exporting HTML reports. HTMX handles dynamic partial updates
without a JavaScript framework.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from vxis.core.db import create_engine, get_session, init_db
from vxis.core.events import ScanEventBus
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

# ---------------------------------------------------------------------------
# Token-based authentication middleware
# ---------------------------------------------------------------------------

# Paths that are always accessible without a token.
_PUBLIC_PATHS: set[str] = {"/health", "/login"}


def _get_dashboard_token() -> str | None:
    """Return the configured dashboard token, or None if auth is disabled.

    Reads from ``VXIS_DASHBOARD_TOKEN`` env var each time so that tests
    (or runtime config changes) take effect without restarting.
    """
    return os.environ.get("VXIS_DASHBOARD_TOKEN") or None


class _TokenAuthMiddleware(BaseHTTPMiddleware):
    """Require a Bearer token or ``?token=`` query param when a dashboard token is configured."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        token = _get_dashboard_token()

        # If no token is configured, auth is disabled — pass everything through.
        if token is None:
            return await call_next(request)

        path = request.url.path

        # Always allow public paths.
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        # Check Authorization header (Bearer <token>).
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer ") and auth_header[7:] == token:
            return await call_next(request)

        # Check query parameter ``?token=<token>``.
        query_token = request.query_params.get("token")
        if query_token == token:
            return await call_next(request)

        # Unauthenticated — decide between JSON 401 or redirect to login page.
        # HTMX requests and non-browser API calls get a JSON 401.
        if (
            request.headers.get("hx-request")
            or "text/html" not in request.headers.get("accept", "")
        ):
            return JSONResponse(
                {"detail": "Authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Browser navigation — redirect to the login page.
        return RedirectResponse(url="/login", status_code=303)


app.add_middleware(_TokenAuthMiddleware)

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


@app.get("/clients", response_class=HTMLResponse)
async def clients_list(request: Request) -> HTMLResponse:
    """Clients management page — lists all configured clients with scan history summary."""
    from vxis.config.client_manager import ClientManager

    clients_dir = Path.home() / ".vxis" / "clients"
    manager = ClientManager(clients_dir)
    clients = manager.list_clients()

    engine = _get_engine(request)

    # Build per-client scan summaries
    client_summaries: list[dict] = []
    async with get_session(engine) as session:
        for client in clients:
            total_scans = 0
            total_findings = 0
            latest_scan = None

            for domain in client.domains:
                stmt = (
                    select(ScanRecord)
                    .where(ScanRecord.target.like(f"%{domain}%"))
                    .order_by(ScanRecord.started_at.desc())
                )
                rows = list((await session.execute(stmt)).scalars().all())
                total_scans += len(rows)

                if rows and latest_scan is None:
                    latest_scan = rows[0]

                for scan in rows:
                    count_stmt = select(func.count(FindingRecord.id)).where(
                        FindingRecord.scan_id == scan.id
                    )
                    count: int = (await session.execute(count_stmt)).scalar_one_or_none() or 0
                    total_findings += count

            client_summaries.append(
                {
                    "client": client,
                    "total_scans": total_scans,
                    "total_findings": total_findings,
                    "latest_scan": latest_scan,
                }
            )

    return templates.TemplateResponse(
        request,
        "clients.html",
        {
            "client_summaries": client_summaries,
            "total_clients": len(clients),
        },
    )


@app.get("/client/{client_id}", response_class=HTMLResponse)
async def client_detail(request: Request, client_id: str) -> HTMLResponse:
    """Client detail page — client info, scan history table, and risk trend."""
    from vxis.config.client_manager import ClientManager

    clients_dir = Path.home() / ".vxis" / "clients"
    manager = ClientManager(clients_dir)
    client = manager.get_client(client_id)

    if client is None:
        return templates.TemplateResponse(
            request,
            "404.html",
            {"message": f"Client '{client_id}' not found"},
            status_code=404,
        )

    engine = _get_engine(request)

    # Collect scan history across all client domains
    scan_history: list[dict] = []
    async with get_session(engine) as session:
        for domain in client.domains:
            stmt = (
                select(ScanRecord)
                .where(ScanRecord.target.like(f"%{domain}%"))
                .order_by(ScanRecord.started_at.desc())
            )
            rows = list((await session.execute(stmt)).scalars().all())
            for scan in rows:
                count_stmt = select(func.count(FindingRecord.id)).where(
                    FindingRecord.scan_id == scan.id
                )
                finding_count: int = (
                    await session.execute(count_stmt)
                ).scalar_one_or_none() or 0

                # Severity breakdown for risk grade
                sev_stmt = (
                    select(FindingRecord.effective_severity, func.count(FindingRecord.id))
                    .where(FindingRecord.scan_id == scan.id)
                    .group_by(FindingRecord.effective_severity)
                )
                sev_rows = list((await session.execute(sev_stmt)).all())
                sev_counts: dict[str, int] = {
                    sev: cnt for sev, cnt in sev_rows
                }

                # Compute a simple risk grade (A-F) based on critical/high count
                critical_count = sev_counts.get("critical", 0)
                high_count = sev_counts.get("high", 0)
                if critical_count > 0:
                    grade = "F"
                elif high_count >= 3:
                    grade = "D"
                elif high_count > 0:
                    grade = "C"
                elif sev_counts.get("medium", 0) > 0:
                    grade = "B"
                else:
                    grade = "A"

                scan_history.append(
                    {
                        "scan": scan,
                        "finding_count": finding_count,
                        "sev_counts": sev_counts,
                        "grade": grade,
                    }
                )

    # Sort combined history by started_at descending
    scan_history.sort(
        key=lambda x: x["scan"].started_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    return templates.TemplateResponse(
        request,
        "client_detail.html",
        {
            "client": client,
            "scan_history": scan_history,
            "total_scans": len(scan_history),
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = Query(None)) -> HTMLResponse:
    """Simple login page that asks for the dashboard token."""
    if _get_dashboard_token() is None:
        return RedirectResponse(url="/", status_code=303)  # type: ignore[return-value]
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": error},
    )


@app.post("/login")
async def login_submit(request: Request) -> RedirectResponse:
    """Validate the submitted token and redirect to the dashboard."""
    form = await request.form()
    submitted_token = form.get("token", "")

    token = _get_dashboard_token()

    if token is None:
        return RedirectResponse(url="/", status_code=303)

    if submitted_token == token:
        # Redirect with the token as a query parameter so the middleware allows it.
        # For a simple internal tool this is acceptable; the token stays in the URL.
        return RedirectResponse(url=f"/?token={token}", status_code=303)

    return RedirectResponse(url="/login?error=invalid", status_code=303)


# ---------------------------------------------------------------------------
# Running scans registry
# ---------------------------------------------------------------------------

_running_scans: dict[str, asyncio.Task] = {}
_scan_buses: dict[str, ScanEventBus] = {}


# ---------------------------------------------------------------------------
# Feature 1: Scan Launch Form + Background Scan
# ---------------------------------------------------------------------------


@app.get("/scan/new", response_class=HTMLResponse)
async def scan_new(request: Request) -> HTMLResponse:
    """Render the new scan launch form."""
    return templates.TemplateResponse(request, "scan_new.html", {})


@app.post("/api/scan")
async def api_scan_start(request: Request) -> JSONResponse:
    """Start a scan in the background and return the scan ID."""
    body = await request.json()
    target: str = body.get("target", "").strip()
    profile: str = body.get("profile", "standard")

    if not target:
        return JSONResponse({"error": "target is required"}, status_code=400)

    scan_id = uuid.uuid4().hex[:12]
    event_bus = ScanEventBus()
    _scan_buses[scan_id] = event_bus

    async def _run_scan() -> None:
        from vxis.config.schema import VXISConfig
        from vxis.core.orchestrator import ScanOrchestrator

        try:
            config = VXISConfig()
            orchestrator = ScanOrchestrator(config, event_bus=event_bus)
            await orchestrator.run_scan(target=target, profile=profile)
        except Exception as exc:
            from vxis.core.events import EventType, ScanLifecycleEvent

            await event_bus.emit(
                ScanLifecycleEvent(
                    event_type=EventType.SCAN_FAILED,
                    scan_id=scan_id,
                    error=str(exc),
                )
            )
        finally:
            # Clean up after a delay so SSE clients can receive final events
            await asyncio.sleep(5)
            _running_scans.pop(scan_id, None)
            _scan_buses.pop(scan_id, None)

    task = asyncio.create_task(_run_scan())
    _running_scans[scan_id] = task

    return JSONResponse({"scan_id": scan_id, "status": "started"})


@app.get("/api/scan/{scan_id}/stream")
async def api_scan_stream(scan_id: str) -> StreamingResponse:
    """SSE endpoint that streams scan events in real time."""

    async def _event_generator():
        event_bus = _scan_buses.get(scan_id)
        if event_bus is None:
            yield f"data: {json.dumps({'error': 'Scan not found', 'scan_id': scan_id})}\n\n"
            return

        queue: asyncio.Queue = asyncio.Queue()

        async def _enqueue(event: Any) -> None:
            from dataclasses import asdict
            await queue.put(asdict(event))

        event_bus.on_any(_enqueue)

        try:
            while True:
                try:
                    event_data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(event_data, default=str)}\n\n"
                    # Close stream on terminal events
                    etype = event_data.get("event_type", "")
                    if etype in ("scan.completed", "scan.failed"):
                        break
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield ": keepalive\n\n"
                    # Check if scan is still running
                    if scan_id not in _running_scans:
                        yield f"data: {json.dumps({'event_type': 'scan.completed', 'scan_id': scan_id, 'detail': 'stream closed'})}\n\n"
                        break
        finally:
            event_bus.off_any(_enqueue) if hasattr(event_bus, "off_any") else None

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Feature 2: Plugin Status Page
# ---------------------------------------------------------------------------


@app.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request) -> HTMLResponse:
    """Plugin status page — discover all plugins and show availability."""
    from vxis.plugins.registry import discover_plugins

    registry = discover_plugins()

    plugin_rows: list[dict[str, Any]] = []
    for name, plugin in sorted(registry.items()):
        meta = plugin.meta
        available = plugin.validate_environment()
        plugin_rows.append(
            {
                "name": meta.name,
                "version": meta.version,
                "category": meta.category,
                "binary": meta.tool_binary,
                "tier": meta.tier,
                "available": available,
            }
        )

    return templates.TemplateResponse(
        request,
        "plugins.html",
        {"plugins": plugin_rows, "total_plugins": len(plugin_rows)},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}
