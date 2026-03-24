"""Trend visualization routes for the VXIS dashboard.

Provides portfolio-wide and per-target trend analysis pages with SVG
line charts and summary tables.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from vxis.core.db import create_engine, get_session
from vxis.models.db_models import FindingRecord, ScanRecord

router = APIRouter()

_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

_DEFAULT_DB_URL = "sqlite+aiosqlite:///vxis.db"
_engine = create_engine(_DEFAULT_DB_URL)

# Severity weights — same as vxis.core.trend._SEVERITY_WEIGHTS
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
    "informational": 0.1,
}

_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "informational"]


def _get_engine(request: Request):
    """Return the engine from app state (allows test overrides) or the default."""
    return getattr(request.app.state, "engine", _engine)


def _compute_risk_score(severity_counts: dict[str, int], total: int) -> float:
    """Weighted risk score normalised to 0-10 scale."""
    if total == 0:
        return 0.0
    raw = sum(_SEVERITY_WEIGHTS.get(sev, 0.0) * count for sev, count in severity_counts.items())
    max_possible = _SEVERITY_WEIGHTS["critical"] * total
    if max_possible == 0:
        return 0.0
    return round(min((raw / max_possible) * 10.0, 10.0), 2)


async def _build_trend_data(
    request: Request,
    target: str | None = None,
    limit: int = 30,
) -> list[dict]:
    """Query scans (optionally filtered by target) and build trend rows."""
    engine = _get_engine(request)

    async with get_session(engine) as session:
        stmt = (
            select(ScanRecord)
            .options(selectinload(ScanRecord.findings))
            .order_by(ScanRecord.started_at.asc())
            .limit(limit)
        )
        if target:
            stmt = stmt.where(ScanRecord.target == target)

        result = await session.execute(stmt)
        scans: list[ScanRecord] = list(result.scalars().all())

    rows: list[dict] = []
    for scan in scans:
        counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        for f in scan.findings:
            sev = (f.effective_severity or f.severity).lower()
            if sev in counts:
                counts[sev] += 1

        total = sum(counts.values())
        risk = _compute_risk_score(counts, total)

        rows.append(
            {
                "scan_id": scan.id,
                "target": scan.target,
                "date": scan.started_at,
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "info": counts["informational"],
                "total": total,
                "risk_score": risk,
            }
        )

    return rows


@router.get("/trend", response_class=HTMLResponse)
async def trend_portfolio(request: Request) -> HTMLResponse:
    """Portfolio-wide trend analysis page."""
    rows = await _build_trend_data(request)
    return templates.TemplateResponse(
        request,
        "trend.html",
        {
            "title": "Portfolio Trend",
            "target": None,
            "rows": rows,
        },
    )


@router.get("/trend/{target:path}", response_class=HTMLResponse)
async def trend_target(request: Request, target: str) -> HTMLResponse:
    """Per-target trend analysis page."""
    rows = await _build_trend_data(request, target=target)
    return templates.TemplateResponse(
        request,
        "trend.html",
        {
            "title": f"Trend Analysis: {target}",
            "target": target,
            "rows": rows,
        },
    )
