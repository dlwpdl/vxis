"""VXIS web dashboard — FastAPI application.

Provides a server-side-rendered web UI for viewing scan results, filtering
findings, and exporting HTML reports. HTMX handles dynamic partial updates
without a JavaScript framework.
"""

from __future__ import annotations

import os
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

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
    try:
        from vxis.dashboard.auth import ensure_default_admin

        await ensure_default_admin(engine)
    except Exception:
        pass
    yield


app = FastAPI(title="VXIS Dashboard", version="0.1.0", lifespan=_lifespan)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# ---------------------------------------------------------------------------
# Token-based authentication middleware
# ---------------------------------------------------------------------------

# Paths that are always accessible without a token.
_PUBLIC_PATHS: set[str] = {"/health", "/login", "/logout"}


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
    format: str = Query("html", description="Export format: html, docx, attestation"),
) -> FileResponse:
    """Export a scan report. Supports html, docx, and attestation formats."""
    from datetime import date
    from pathlib import Path as FilePath

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

    safe_target = scan.target.replace("/", "_")
    scan_date = scan.started_at.strftime("%Y-%m-%d") if scan.started_at else str(date.today())

    report_data = ReportData(
        scan_id=str(scan_id),
        client_name=scan.target,
        target=scan.target,
        scan_date=scan_date,
        findings=findings,
    )

    if format == "docx":
        try:
            from vxis.report.docx_export import DOCXReportGenerator
        except ImportError:
            error_html = (
                "<html><body style='font-family:sans-serif;padding:2rem'>"
                "<h2>DOCX 내보내기를 사용할 수 없습니다</h2>"
                "<p><code>python-docx</code> 패키지가 설치되지 않았습니다.</p>"
                "<p>설치 방법: <code>pip install python-docx</code></p>"
                "</body></html>"
            )
            return HTMLResponse(content=error_html, status_code=503)  # type: ignore[return-value]

        tmp_path = FilePath(tempfile.mktemp(suffix=".docx", prefix=f"vxis_report_{scan_id}_"))
        DOCXReportGenerator().generate(report_data, tmp_path)
        filename = f"vxis_report_{safe_target}_{scan_id}.docx"
        return FileResponse(
            path=str(tmp_path),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if format == "attestation":
        try:
            from vxis.report.attestation import AttestationGenerator
        except ImportError:
            error_html = (
                "<html><body style='font-family:sans-serif;padding:2rem'>"
                "<h2>Attestation 내보내기를 사용할 수 없습니다</h2>"
                "<p><code>python-docx</code> 패키지가 설치되지 않았습니다.</p>"
                "<p>설치 방법: <code>pip install python-docx</code></p>"
                "</body></html>"
            )
            return HTMLResponse(content=error_html, status_code=503)  # type: ignore[return-value]

        tmp_path = FilePath(tempfile.mktemp(suffix=".docx", prefix=f"vxis_attestation_{scan_id}_"))
        AttestationGenerator().generate(report_data, tmp_path)
        filename = f"vxis_attestation_{safe_target}_{scan_id}.docx"
        return FileResponse(
            path=str(tmp_path),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Default: html
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

    filename = f"vxis_report_{safe_target}_{scan_id}.html"

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
    """Login page — supports both user credentials and dashboard token."""
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": error, "token_required": _get_dashboard_token() is not None},
    )


@app.post("/login")
async def login_submit(request: Request):  # type: ignore[no-untyped-def]
    """Validate submitted credentials and create a session cookie."""
    from vxis.dashboard.auth import (
        set_session_cookie,
        verify_password,
    )
    from vxis.models.db_models import UserRecord

    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    submitted_token = str(form.get("token", ""))

    # Optional dashboard token still honoured (kept in URL for middleware).
    token = _get_dashboard_token()
    token_qs = ""
    if token is not None:
        if submitted_token != token:
            return RedirectResponse(url="/login?error=invalid", status_code=303)
        token_qs = f"?token={token}"

    if not username or not password:
        return RedirectResponse(url="/login?error=invalid", status_code=303)

    engine = _get_engine(request)
    async with get_session(engine) as session:
        result = await session.execute(
            select(UserRecord).where(UserRecord.username == username)
        )
        user = result.scalar_one_or_none()

    if user is None or not verify_password(password, user.password_hash):
        return RedirectResponse(url="/login?error=invalid", status_code=303)

    response = RedirectResponse(url=f"/{token_qs}", status_code=303)
    set_session_cookie(response, user.id)
    return response


@app.get("/logout")
async def logout(request: Request):  # type: ignore[no-untyped-def]
    from vxis.dashboard.auth import clear_session_cookie

    response = RedirectResponse(url="/login", status_code=303)
    clear_session_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Scan from Dashboard — start, live view, SSE events
# ---------------------------------------------------------------------------

@app.get("/scan/new", response_class=HTMLResponse)
async def scan_new_page(request: Request) -> HTMLResponse:
    """Scan start form page."""
    scan_types = [
        ("zero_touch", "제로터치 (Passive)", "\U0001f50d", "대상에 접촉 없이 OSINT만으로 정보 수집"),
        ("external", "외부 스캔", "\U0001f310", "웹/네트워크 취약점 + SSL/DNS 진단"),
        ("internal", "내부 스캔", "\U0001f3e2", "AD/내부 네트워크 환경 진단"),
        ("code", "코드 스캔", "\U0001f4bb", "소스코드 + 의존성 + CI/CD 보안"),
        ("cloud", "클라우드", "\u2601\ufe0f", "AWS/Azure/GCP 설정 감사"),
        ("full", "전체 스캔", "\U0001f680", "모든 플러그인 실행"),
    ]
    return templates.TemplateResponse(
        request, "scan_new.html", {"scan_types": scan_types},
    )


@app.post("/api/scan/start", response_class=HTMLResponse)
async def scan_start_api(request: Request) -> HTMLResponse:
    """Start a scan from dashboard form. Returns redirect to live view."""
    from vxis.dashboard.scan_manager import scan_manager, SCAN_TYPE_LABELS

    form = await request.form()
    target = str(form.get("target", "")).strip()
    scan_type = str(form.get("scan_type", "external"))
    profile = str(form.get("profile", ""))

    if not target:
        return HTMLResponse(
            '<p class="text-red-400 text-sm">스캔 대상을 입력하세요.</p>',
            status_code=400,
        )

    managed = await scan_manager.start_scan(
        target=target,
        scan_type=scan_type,
        profile=profile or None,
    )

    # Return HTMX redirect to live page
    label = SCAN_TYPE_LABELS.get(scan_type, scan_type)
    return HTMLResponse(
        f'<script>window.location.href="/scan/{managed.scan_id}/live";</script>'
        f'<p class="text-cyan-400">스캔 시작됨: {managed.scan_id} → 라이브 페이지로 이동 중...</p>',
    )


@app.get("/scan/{scan_id}/live", response_class=HTMLResponse)
async def scan_live_page(request: Request, scan_id: str) -> HTMLResponse:
    """Live scan progress page with SSE."""
    from vxis.dashboard.scan_manager import scan_manager, SCAN_TYPE_LABELS

    managed = scan_manager.get_scan(scan_id)
    if managed is None:
        return templates.TemplateResponse(
            request, "404.html",
            {"message": f"스캔 {scan_id}를 찾을 수 없습니다"},
            status_code=404,
        )

    label = SCAN_TYPE_LABELS.get(managed.scan_type, managed.scan_type)

    return templates.TemplateResponse(
        request, "scan_live.html",
        {
            "scan_id": scan_id,
            "target": managed.target,
            "profile": managed.profile,
            "scan_type_label": label,
        },
    )


@app.get("/api/scan/{scan_id}/events")
async def scan_sse_events(request: Request, scan_id: str):
    """SSE endpoint — streams scan events in real-time."""
    import asyncio
    import json
    from starlette.responses import StreamingResponse
    from vxis.dashboard.scan_manager import scan_manager

    managed = scan_manager.get_scan(scan_id)
    if managed is None:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    queue = scan_manager.subscribe(scan_id)
    if queue is None:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    async def _event_generator():
        """Yield SSE events from the queue."""
        try:
            # Send initial snapshot
            snapshot = managed.collector.snapshot
            initial = {
                "event": "connected",
                "progress": f"{snapshot.progress_fraction:.0%}",
                "completed": snapshot.completed_count,
                "total": snapshot.total_count,
                "running": snapshot.running_count,
                "findings": snapshot.total_findings,
                "severity": snapshot.severity_counts,
                "elapsed": f"{snapshot.elapsed_seconds:.0f}s",
                "stage": snapshot.pipeline_stage,
            }
            yield f"data: {json.dumps(initial)}\n\n"

            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {json.dumps(data)}\n\n"

                    # Stop streaming after completion/failure
                    if data.get("event") in ("scan_completed", "scan_failed"):
                        yield f"data: {json.dumps({'event': 'done'})}\n\n"
                        break

                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield f": keepalive\n\n"

                # Check if client disconnected
                if await request.is_disconnected():
                    break

        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Live / Trends / Phases — read-only dashboards
# ---------------------------------------------------------------------------

# Severity weights used for time-series scoring fallback (no persisted vxis_score).
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
    "informational": 0.1,
}


def _risk_score(sev_counts: dict[str, int]) -> float:
    """Weighted severity score (higher = worse). Used as VXIS-score fallback."""
    return round(
        sum(_SEVERITY_WEIGHTS.get(s, 0.0) * c for s, c in sev_counts.items()),
        2,
    )


@app.get("/scans/active", response_class=HTMLResponse)
async def scans_active(request: Request) -> HTMLResponse:
    """Live scan status — running scans + recent findings (HTMX polling)."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        running_result = await session.execute(
            select(ScanRecord)
            .where(ScanRecord.status == "running")
            .order_by(ScanRecord.started_at.desc())
        )
        running_scans: list[ScanRecord] = list(running_result.scalars().all())

        # Per-scan finding counts
        scan_rows: list[dict] = []
        for scan in running_scans:
            count_stmt = select(func.count(FindingRecord.id)).where(
                FindingRecord.scan_id == scan.id
            )
            f_count: int = (await session.execute(count_stmt)).scalar_one_or_none() or 0

            cfg = scan.config_snapshot or {}
            phases_completed = int(cfg.get("phases_completed", 0) or 0)
            total_phases = int(cfg.get("total_phases", 0) or 0)
            pct = (
                round(100.0 * phases_completed / total_phases, 1)
                if total_phases > 0
                else 0.0
            )
            scan_rows.append(
                {
                    "scan": scan,
                    "finding_count": f_count,
                    "phases_completed": phases_completed,
                    "total_phases": total_phases,
                    "progress_pct": pct,
                }
            )

        # Recent findings across all scans (last 20)
        recent_result = await session.execute(
            select(FindingRecord)
            .order_by(FindingRecord.discovered_at.desc())
            .limit(20)
        )
        recent_findings: list[FindingRecord] = list(recent_result.scalars().all())

    return templates.TemplateResponse(
        request,
        "scans_active.html",
        {
            "scan_rows": scan_rows,
            "recent_findings": recent_findings,
        },
    )


@app.get("/scans/active/partial", response_class=HTMLResponse)
async def scans_active_partial(request: Request) -> HTMLResponse:
    """HTMX partial — refreshed every 5s by /scans/active page."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        running_result = await session.execute(
            select(ScanRecord)
            .where(ScanRecord.status == "running")
            .order_by(ScanRecord.started_at.desc())
        )
        running_scans: list[ScanRecord] = list(running_result.scalars().all())

        scan_rows: list[dict] = []
        for scan in running_scans:
            count_stmt = select(func.count(FindingRecord.id)).where(
                FindingRecord.scan_id == scan.id
            )
            f_count: int = (await session.execute(count_stmt)).scalar_one_or_none() or 0
            cfg = scan.config_snapshot or {}
            phases_completed = int(cfg.get("phases_completed", 0) or 0)
            total_phases = int(cfg.get("total_phases", 0) or 0)
            pct = (
                round(100.0 * phases_completed / total_phases, 1)
                if total_phases > 0
                else 0.0
            )
            scan_rows.append(
                {
                    "scan": scan,
                    "finding_count": f_count,
                    "phases_completed": phases_completed,
                    "total_phases": total_phases,
                    "progress_pct": pct,
                }
            )

        recent_result = await session.execute(
            select(FindingRecord)
            .order_by(FindingRecord.discovered_at.desc())
            .limit(20)
        )
        recent_findings: list[FindingRecord] = list(recent_result.scalars().all())

    return templates.TemplateResponse(
        request,
        "partials/scans_active.html",
        {
            "scan_rows": scan_rows,
            "recent_findings": recent_findings,
        },
    )


def _line_chart_svg(
    points: list[tuple[str, float]],
    width: int = 640,
    height: int = 220,
    stroke: str = "#22d3ee",
) -> str:
    """Render a minimal SVG line chart from (label, value) points."""
    if not points:
        return (
            f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
            f'<text x="{width/2}" y="{height/2}" text-anchor="middle" fill="#64748b" '
            f'font-family="sans-serif" font-size="13">No data</text></svg>'
        )

    pad_l, pad_r, pad_t, pad_b = 40, 20, 20, 36
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    values = [v for _, v in points]
    vmax = max(values) if values else 1.0
    vmin = min(values) if values else 0.0
    if vmax == vmin:
        vmax = vmin + 1.0

    n = len(points)
    step = plot_w / max(n - 1, 1)

    coords: list[tuple[float, float]] = []
    for i, (_, v) in enumerate(points):
        x = pad_l + i * step
        y = pad_t + plot_h - ((v - vmin) / (vmax - vmin)) * plot_h
        coords.append((x, y))

    path = "M " + " L ".join(f"{x:.1f} {y:.1f}" for x, y in coords)

    # Gridlines (3)
    grid = ""
    for i in range(4):
        gy = pad_t + (plot_h * i / 3)
        gv = vmax - (vmax - vmin) * i / 3
        grid += (
            f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{pad_l + plot_w}" y2="{gy:.1f}" '
            f'stroke="#1f2937" stroke-width="1"/>'
            f'<text x="{pad_l - 6}" y="{gy + 3:.1f}" text-anchor="end" fill="#64748b" '
            f'font-family="sans-serif" font-size="10">{gv:.1f}</text>'
        )

    # Points + labels (only every Nth label to avoid clutter)
    label_every = max(1, n // 6)
    dots = ""
    labels = ""
    for i, ((lab, _v), (x, y)) in enumerate(zip(points, coords)):
        dots += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{stroke}"/>'
        if i % label_every == 0 or i == n - 1:
            labels += (
                f'<text x="{x:.1f}" y="{height - 10}" text-anchor="middle" '
                f'fill="#94a3b8" font-family="sans-serif" font-size="10">{lab}</text>'
            )

    return (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'class="w-full h-auto">'
        f'{grid}'
        f'<path d="{path}" fill="none" stroke="{stroke}" stroke-width="2"/>'
        f'{dots}{labels}'
        f'</svg>'
    )


templates.env.globals["line_chart_svg"] = _line_chart_svg


@app.get("/trends", response_class=HTMLResponse)
async def trends_page(request: Request) -> HTMLResponse:
    """Per-target VXIS-score (weighted-severity fallback) trend over last 10 scans."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        scans_result = await session.execute(
            select(ScanRecord).order_by(ScanRecord.started_at.desc())
        )
        all_scans: list[ScanRecord] = list(scans_result.scalars().all())

        # Group by target, keep most recent 10 each (oldest-first for plotting)
        per_target: dict[str, list[ScanRecord]] = {}
        for scan in all_scans:
            per_target.setdefault(scan.target, []).append(scan)

        target_series: list[dict] = []
        for target, scans in per_target.items():
            recent = list(reversed(scans[:10]))  # oldest -> newest
            points: list[tuple[str, float]] = []
            for scan in recent:
                sev_stmt = (
                    select(FindingRecord.effective_severity, func.count(FindingRecord.id))
                    .where(FindingRecord.scan_id == scan.id)
                    .group_by(FindingRecord.effective_severity)
                )
                sev_rows = list((await session.execute(sev_stmt)).all())
                sev_counts = {sev: cnt for sev, cnt in sev_rows}
                score = _risk_score(sev_counts)
                label = (
                    scan.started_at.strftime("%m-%d")
                    if scan.started_at
                    else f"#{scan.id}"
                )
                points.append((label, score))

            target_series.append(
                {
                    "target": target,
                    "points": points,
                    "scan_count": len(recent),
                    "latest_score": points[-1][1] if points else 0.0,
                }
            )

        target_series.sort(key=lambda d: d["latest_score"], reverse=True)

    return templates.TemplateResponse(
        request,
        "trends.html",
        {"target_series": target_series},
    )


@app.get("/phases", response_class=HTMLResponse)
async def phases_page(request: Request) -> HTMLResponse:
    """Per-phase performance — avg duration, failure rate, finding counts.

    Uses ToolRunRecord (per-tool/per-plugin invocations) as the closest analogue
    to "phases" since phases are not persisted as a separate table.
    """
    from vxis.models.db_models import ToolRunRecord

    engine = _get_engine(request)

    async with get_session(engine) as session:
        rows_result = await session.execute(
            select(
                ToolRunRecord.plugin_name,
                func.count(ToolRunRecord.id),
                func.avg(ToolRunRecord.elapsed_seconds),
                func.sum(
                    case((ToolRunRecord.state == "failed", 1), else_=0)
                ),
                func.sum(
                    case((ToolRunRecord.state == "timeout", 1), else_=0)
                ),
            ).group_by(ToolRunRecord.plugin_name)
        )

        finding_rows = await session.execute(
            select(FindingRecord.source_plugin, func.count(FindingRecord.id)).group_by(
                FindingRecord.source_plugin
            )
        )
        findings_by_plugin: dict[str, int] = {
            row[0]: row[1] for row in finding_rows.all()
        }

    phase_rows: list[dict] = []
    for plugin, total, avg_elapsed, failed, timed_out in rows_result.all():
        total = int(total or 0)
        failed = int(failed or 0)
        timed_out = int(timed_out or 0)
        bad = failed + timed_out
        fail_rate = round(100.0 * bad / total, 1) if total else 0.0
        phase_rows.append(
            {
                "name": plugin,
                "runs": total,
                "avg_seconds": round(float(avg_elapsed or 0.0), 2),
                "failed": bad,
                "fail_rate": fail_rate,
                "findings": findings_by_plugin.get(plugin, 0),
            }
        )

    phase_rows.sort(key=lambda d: d["runs"], reverse=True)

    return templates.TemplateResponse(
        request,
        "phases.html",
        {"phase_rows": phase_rows},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}


# ---------------------------------------------------------------------------
# Multi-user collaboration: users, comments, reviews
# ---------------------------------------------------------------------------


def _expose_current_user_to_templates() -> None:
    """Inject ``current_user`` (resolved per-request) via Jinja2 globals.

    Templates use ``request.state.user`` instead — populated by the
    middleware below.
    """


@app.middleware("http")
async def _populate_user_state(request: Request, call_next):  # type: ignore[no-untyped-def]
    from vxis.dashboard.auth import current_user

    try:
        request.state.user = await current_user(request)
    except Exception:
        request.state.user = None
    return await call_next(request)


@app.get("/users", response_class=HTMLResponse)
async def users_list(request: Request) -> HTMLResponse:
    """Admin-only list of dashboard users."""
    from vxis.dashboard.auth import current_user
    from vxis.models.db_models import UserRecord

    user = await current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)  # type: ignore[return-value]
    if user.role != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    engine = _get_engine(request)
    async with get_session(engine) as session:
        result = await session.execute(
            select(UserRecord).order_by(UserRecord.created_at.desc())
        )
        users = list(result.scalars().all())

    return templates.TemplateResponse(
        request, "users.html", {"users": users, "current_user": user},
    )


@app.post("/users")
async def users_create(request: Request):  # type: ignore[no-untyped-def]
    """Admin-only — create a new user."""
    from vxis.dashboard.auth import current_user, hash_password
    from vxis.models.db_models import UserRecord

    user = await current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    if user.role != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    form = await request.form()
    username = str(form.get("username", "")).strip()
    email = str(form.get("email", "")).strip() or None
    role = str(form.get("role", "viewer")).strip() or "viewer"
    password = str(form.get("password", ""))

    if not username or not password or role not in {"viewer", "reviewer", "admin"}:
        return RedirectResponse(url="/users", status_code=303)

    engine = _get_engine(request)
    async with get_session(engine) as session:
        existing = (
            await session.execute(select(UserRecord).where(UserRecord.username == username))
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                UserRecord(
                    username=username,
                    email=email,
                    role=role,
                    password_hash=hash_password(password),
                )
            )

    return RedirectResponse(url="/users", status_code=303)


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail_page(request: Request, finding_id: int) -> HTMLResponse:
    """Single-finding detail page including comments + review status."""
    from vxis.dashboard.auth import current_user
    from vxis.models.db_models import (
        FindingCommentRecord,
        FindingReviewRecord,
        UserRecord,
    )

    user = await current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)  # type: ignore[return-value]

    engine = _get_engine(request)
    async with get_session(engine) as session:
        finding = (
            await session.execute(
                select(FindingRecord).where(FindingRecord.id == finding_id)
            )
        ).scalar_one_or_none()
        if finding is None:
            return templates.TemplateResponse(
                request, "404.html", {"message": "Finding not found"}, status_code=404,
            )
        scan = (
            await session.execute(
                select(ScanRecord).where(ScanRecord.id == finding.scan_id)
            )
        ).scalar_one_or_none()

        comments_rows = (
            await session.execute(
                select(FindingCommentRecord, UserRecord)
                .join(UserRecord, UserRecord.id == FindingCommentRecord.user_id)
                .where(FindingCommentRecord.finding_id == finding_id)
                .order_by(FindingCommentRecord.created_at.asc())
            )
        ).all()
        comments = [
            {"comment": c, "user": u} for c, u in comments_rows
        ]

        review = (
            await session.execute(
                select(FindingReviewRecord)
                .where(FindingReviewRecord.finding_id == finding_id)
                .order_by(FindingReviewRecord.reviewed_at.desc())
            )
        ).scalars().first()

    return templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "finding": finding,
            "scan": scan,
            "scan_id": scan.id if scan else None,
            "comments": comments,
            "review": review,
            "current_user": user,
            "collab": True,
        },
    )


@app.get("/findings/{finding_id}/comments", response_class=HTMLResponse)
async def finding_comments_partial(request: Request, finding_id: int) -> HTMLResponse:
    """HTMX partial — comments list for a finding."""
    from vxis.dashboard.auth import current_user
    from vxis.models.db_models import FindingCommentRecord, UserRecord

    user = await current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    engine = _get_engine(request)
    async with get_session(engine) as session:
        rows = (
            await session.execute(
                select(FindingCommentRecord, UserRecord)
                .join(UserRecord, UserRecord.id == FindingCommentRecord.user_id)
                .where(FindingCommentRecord.finding_id == finding_id)
                .order_by(FindingCommentRecord.created_at.asc())
            )
        ).all()
        comments = [{"comment": c, "user": u} for c, u in rows]

    return templates.TemplateResponse(
        request,
        "partials/comments.html",
        {"comments": comments, "finding_id": finding_id, "current_user": user},
    )


@app.post("/findings/{finding_id}/comments", response_class=HTMLResponse)
async def finding_comments_create(
    request: Request, finding_id: int
) -> HTMLResponse:
    """Add a comment to a finding (any authenticated user)."""
    from vxis.dashboard.auth import current_user
    from vxis.models.db_models import FindingCommentRecord, UserRecord

    user = await current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    form = await request.form()
    content = str(form.get("content", "")).strip()
    if not content:
        return await finding_comments_partial(request, finding_id)

    engine = _get_engine(request)
    async with get_session(engine) as session:
        session.add(
            FindingCommentRecord(
                finding_id=finding_id,
                user_id=user.id,
                content=content,
            )
        )

    # Return refreshed partial
    async with get_session(engine) as session:
        rows = (
            await session.execute(
                select(FindingCommentRecord, UserRecord)
                .join(UserRecord, UserRecord.id == FindingCommentRecord.user_id)
                .where(FindingCommentRecord.finding_id == finding_id)
                .order_by(FindingCommentRecord.created_at.asc())
            )
        ).all()
        comments = [{"comment": c, "user": u} for c, u in rows]

    return templates.TemplateResponse(
        request,
        "partials/comments.html",
        {"comments": comments, "finding_id": finding_id, "current_user": user},
    )


@app.post("/findings/{finding_id}/review")
async def finding_review_set(request: Request, finding_id: int):  # type: ignore[no-untyped-def]
    """Set the review status of a finding (reviewer/admin only)."""
    from vxis.dashboard.auth import ROLE_LEVELS, current_user
    from vxis.models.db_models import FindingReviewRecord

    user = await current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    if ROLE_LEVELS.get(user.role, 0) < ROLE_LEVELS["reviewer"]:
        return HTMLResponse("Forbidden", status_code=403)

    form = await request.form()
    status = str(form.get("status", "pending"))
    if status not in {"pending", "approved", "rejected", "false_positive"}:
        status = "pending"

    engine = _get_engine(request)
    async with get_session(engine) as session:
        existing = (
            await session.execute(
                select(FindingReviewRecord).where(
                    FindingReviewRecord.finding_id == finding_id
                )
            )
        ).scalars().first()
        if existing is None:
            session.add(
                FindingReviewRecord(
                    finding_id=finding_id,
                    user_id=user.id,
                    status=status,
                )
            )
        else:
            existing.status = status
            existing.user_id = user.id

    return RedirectResponse(url=f"/findings/{finding_id}", status_code=303)
