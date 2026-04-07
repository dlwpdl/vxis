"""Output primitives — finding storage, scoring, and report generation.

Thin wrappers over vxis.models.finding, vxis.scoring.engine, and
vxis.report.generator. No LLM calls.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# In-memory finding store keyed by scan_id. Replace with DB later if needed.
_finding_store: dict[str, list[dict]] = {}


# ── Finding CRUD ──────────────────────────────────────────────────


def finding_add(scan_id: str, finding_data: dict) -> str:
    """Store a finding dict under the given scan_id and return its finding_id.

    Validates against vxis.models.finding.Finding when possible; falls back
    to storing the raw dict with an auto-generated id otherwise.
    """
    fid = finding_data.get("id") or f"F-{uuid.uuid4().hex[:8].upper()}"
    finding_data = dict(finding_data)
    finding_data["id"] = fid
    finding_data.setdefault("scan_id", scan_id)

    try:
        from vxis.models.finding import Finding

        validated = Finding(**finding_data)
        payload = validated.model_dump()
    except Exception as exc:
        logger.debug("Finding validation failed, storing raw dict: %s", exc)
        payload = finding_data

    _finding_store.setdefault(scan_id, []).append(payload)
    return fid


def finding_list(
    scan_id: str,
    severity_filter: list[str] | None = None,
) -> list[dict]:
    """List findings for a scan, optionally filtered by severity."""
    items = _finding_store.get(scan_id, [])
    if not severity_filter:
        return list(items)
    wanted = {s.lower() for s in severity_filter}
    return [f for f in items if str(f.get("severity", "")).lower() in wanted]


def finding_escalate(finding_id: str, new_level: int) -> dict:
    """Raise the exploitation level of an existing finding."""
    for items in _finding_store.values():
        for f in items:
            if f.get("id") == finding_id:
                f["exploitation_level"] = int(new_level)
                return dict(f)
    return {"error": f"finding not found: {finding_id}"}


# ── Scoring ───────────────────────────────────────────────────────


def score_compute(scan_id: str) -> dict:
    """Compute the 5-dimension VXIS score for a scan.

    Derives target_type from the stored findings (defaults to "web").
    """
    findings = _finding_store.get(scan_id, [])
    target_type = "web"
    for f in findings:
        tt = str(f.get("target_type", "")).lower()
        if tt in ("web", "game", "mobile"):
            target_type = tt
            break

    try:
        from vxis.scoring.engine import ScoringEngine
        from vxis.scoring.tracker import ScoreTracker
    except Exception as exc:
        logger.debug("scoring modules unavailable: %s", exc)
        return {"error": str(exc), "total": 0.0, "grade": "F"}

    tracker = ScoreTracker(target_type=target_type)
    for f in findings:
        fid = f.get("id", "")
        vid = f.get("vector_id", "")
        level = int(f.get("exploitation_level", 1) or 1)
        if vid:
            tracker.record_vector_attempt(vid)
            tracker.record_finding(fid, vid, level)

    engine = ScoringEngine(target_type=target_type)
    try:
        score = engine.calculate(tracker, findings, scan_id=scan_id)
    except Exception as exc:
        logger.debug("score calculate failed: %s", exc)
        return {"error": str(exc), "total": 0.0, "grade": "F"}

    return {
        "scan_id": scan_id,
        "target_type": target_type,
        "total": score.total,
        "grade": score.grade,
        "vector_coverage": score.vector_coverage.score,
        "exploitation_reach": score.exploitation_reach.score,
        "chain_intelligence": score.chain_intelligence.score,
        "finding_precision": score.finding_precision.score,
        "completeness": score.completeness.score,
    }


# ── Report generation ────────────────────────────────────────────


def report_generate(scan_id: str, template: str = "ncc_group") -> str:
    """Render a single HTML report for a scan and return the output path."""
    try:
        from vxis.models.finding import Finding
        from vxis.report.generator import ReportData, ReportGenerator
    except Exception as exc:
        raise RuntimeError(f"report modules unavailable: {exc}") from exc

    raw_findings = _finding_store.get(scan_id, [])
    findings: list[Any] = []
    for f in raw_findings:
        try:
            findings.append(Finding(**f))
        except Exception as exc:
            logger.debug("skip invalid finding %s: %s", f.get("id"), exc)

    target = ""
    for f in raw_findings:
        if f.get("target"):
            target = f["target"]
            break

    data = ReportData(
        scan_id=scan_id,
        client_name="VXIS Target",
        target=target,
        scan_date="",
        findings=findings,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain",
        executive_summary="Automated scan report|||자동 스캔 리포트",
        attack_chains=[],
    )

    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{scan_id}.html"

    gen = ReportGenerator()
    try:
        gen.generate_html_file(data, out_path)
    except Exception as exc:
        logger.warning("generate_html_file failed, falling back to render_html: %s", exc)
        html_text = gen.render_html(data)
        out_path.write_text(html_text)

    return str(out_path.resolve())
