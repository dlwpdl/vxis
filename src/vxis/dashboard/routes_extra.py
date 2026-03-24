"""Extra dashboard routes — Client CRUD, KB Browser, Multi-format Export.

This module defines an ``APIRouter`` that is included by ``app.py``.
"""

from __future__ import annotations

import csv
import io
import json
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from sqlalchemy import select

from vxis.config.client_manager import Client, ClientManager, _slugify
from vxis.core.db import get_session
from vxis.models.db_models import FindingRecord, ScanRecord

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_DB_URL = "sqlite+aiosqlite:///vxis.db"


def _get_engine(request: Request):
    from vxis.dashboard.app import _engine

    return getattr(request.app.state, "engine", _engine)


def _templates(request: Request):
    """Return the Jinja2Templates instance from the app module."""
    from vxis.dashboard.app import templates

    return templates


def _clients_dir() -> Path:
    return Path.home() / ".vxis" / "clients"


# ===================================================================
# Feature 1: Client CRUD
# ===================================================================


@router.get("/client/new", response_class=HTMLResponse)
async def client_new_form(request: Request) -> HTMLResponse:
    """Render an empty client creation form."""
    templates = _templates(request)
    return templates.TemplateResponse(
        request,
        "client_form.html",
        {
            "client": None,
            "editing": False,
            "page_title": "New Client",
        },
    )


@router.post("/api/client")
async def client_create(
    request: Request,
    name: str = Form(...),
    domains: str = Form(""),
    industry: str = Form(""),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
) -> RedirectResponse:
    """Create a new client via ClientManager and redirect to its detail page."""
    manager = ClientManager(_clients_dir())
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    client = Client(
        id=_slugify(name),
        name=name,
        domains=domain_list,
        industry=industry,
        contact_name=contact_name,
        contact_email=contact_email,
    )
    manager.create_client(client)
    return RedirectResponse(url=f"/client/{client.id}", status_code=303)


@router.get("/client/{client_id}/edit", response_class=HTMLResponse)
async def client_edit_form(request: Request, client_id: str) -> HTMLResponse:
    """Render the client form pre-filled with existing data."""
    templates = _templates(request)
    manager = ClientManager(_clients_dir())
    client = manager.get_client(client_id)

    if client is None:
        return templates.TemplateResponse(
            request,
            "404.html",
            {"message": f"Client '{client_id}' not found"},
            status_code=404,
        )

    return templates.TemplateResponse(
        request,
        "client_form.html",
        {
            "client": client,
            "editing": True,
            "page_title": f"Edit {client.name}",
        },
    )


@router.post("/api/client/{client_id}")
async def client_update(
    request: Request,
    client_id: str,
    name: str = Form(...),
    domains: str = Form(""),
    industry: str = Form(""),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
) -> RedirectResponse:
    """Update an existing client's fields and redirect to client detail."""
    manager = ClientManager(_clients_dir())
    client = manager.get_client(client_id)

    if client is None:
        return RedirectResponse(url="/clients", status_code=303)

    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    client.name = name
    client.domains = domain_list
    client.industry = industry
    client.contact_name = contact_name
    client.contact_email = contact_email
    manager.update_client(client)

    return RedirectResponse(url=f"/client/{client_id}", status_code=303)


@router.post("/api/client/{client_id}/delete")
async def client_delete(request: Request, client_id: str) -> RedirectResponse:
    """Delete a client and redirect to the clients list."""
    manager = ClientManager(_clients_dir())
    manager.delete_client(client_id)
    return RedirectResponse(url="/clients", status_code=303)


# ===================================================================
# Feature 2: KB Browser
# ===================================================================


@router.get("/kb", response_class=HTMLResponse)
async def kb_index(request: Request) -> HTMLResponse:
    """Render the full KB browser page with all entries."""
    from vxis.knowledge import get_vuln_kb

    templates = _templates(request)
    kb = get_vuln_kb()
    entries = [kb.get_remediation(t) for t in kb.all_types]
    entries = [e for e in entries if e is not None]

    return templates.TemplateResponse(
        request,
        "kb.html",
        {
            "entries": entries,
            "total_entries": len(entries),
            "query": "",
        },
    )


@router.get("/kb/search", response_class=HTMLResponse)
async def kb_search(
    request: Request,
    q: str = Query(""),
) -> HTMLResponse:
    """HTMX partial: return filtered KB entry cards."""
    from vxis.knowledge import get_vuln_kb

    templates = _templates(request)
    kb = get_vuln_kb()

    if q.strip():
        entries = kb.search(q.strip())
    else:
        entries = [kb.get_remediation(t) for t in kb.all_types]
        entries = [e for e in entries if e is not None]

    return templates.TemplateResponse(
        request,
        "partials/kb_cards.html",
        {
            "entries": entries,
        },
    )


# ===================================================================
# Feature 3: Multi-format Export Enhancement
# ===================================================================


@router.get("/scan/{scan_id}/export")
async def export_report(
    request: Request,
    scan_id: str,
    format: str = Query("html", description="Export format: html|json|csv"),
) -> FileResponse | StreamingResponse:
    """Export a scan as HTML, JSON, or CSV."""
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

    # ---- JSON export ----
    if format == "json":
        findings_data = []
        for rec in records:
            findings_data.append(
                {
                    "id": rec.id,
                    "scan_id": rec.scan_id,
                    "title": rec.title,
                    "description": rec.description,
                    "severity": rec.severity,
                    "effective_severity": rec.effective_severity,
                    "status": rec.status,
                    "finding_type": rec.finding_type,
                    "target": rec.target,
                    "port": rec.port,
                    "protocol": rec.protocol,
                    "affected_component": rec.affected_component,
                    "cvss_score": rec.cvss_score,
                    "cvss_vector": rec.cvss_vector,
                    "cve_ids": rec.cve_ids or [],
                    "cwe_ids": rec.cwe_ids or [],
                    "source_plugin": rec.source_plugin,
                    "confidence": rec.confidence,
                    "remediation": rec.remediation,
                    "discovered_at": rec.discovered_at.isoformat() if rec.discovered_at else None,
                    "updated_at": rec.updated_at.isoformat() if rec.updated_at else None,
                }
            )

        payload = {
            "scan_id": scan.id,
            "target": scan.target,
            "profile": scan.profile,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "findings": findings_data,
        }

        json_bytes = json.dumps(payload, indent=2, default=str).encode("utf-8")
        filename = f"vxis_report_{scan.target.replace('/', '_')}_{scan_id}.json"

        return StreamingResponse(
            iter([json_bytes]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # ---- CSV export ----
    if format == "csv":
        columns = [
            "id",
            "title",
            "severity",
            "effective_severity",
            "status",
            "finding_type",
            "target",
            "port",
            "protocol",
            "affected_component",
            "cvss_score",
            "cvss_vector",
            "cve_ids",
            "cwe_ids",
            "source_plugin",
            "confidence",
            "remediation",
            "discovered_at",
        ]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        for rec in records:
            writer.writerow(
                {
                    "id": rec.id,
                    "title": rec.title,
                    "severity": rec.severity,
                    "effective_severity": rec.effective_severity,
                    "status": rec.status,
                    "finding_type": rec.finding_type,
                    "target": rec.target,
                    "port": rec.port,
                    "protocol": rec.protocol,
                    "affected_component": rec.affected_component,
                    "cvss_score": rec.cvss_score,
                    "cvss_vector": rec.cvss_vector,
                    "cve_ids": ",".join(rec.cve_ids or []),
                    "cwe_ids": ",".join(rec.cwe_ids or []),
                    "source_plugin": rec.source_plugin,
                    "confidence": rec.confidence,
                    "remediation": rec.remediation,
                    "discovered_at": rec.discovered_at.isoformat() if rec.discovered_at else "",
                }
            )

        csv_bytes = output.getvalue().encode("utf-8")
        filename = f"vxis_report_{scan.target.replace('/', '_')}_{scan_id}.csv"

        return StreamingResponse(
            iter([csv_bytes]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # ---- HTML export (default — delegate to existing app.py handler) ----
    # Re-implement HTML export here so the router is self-contained
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
