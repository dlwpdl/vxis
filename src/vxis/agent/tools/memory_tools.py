"""Cross-scan episodic memory — VXIS gets smarter over time.

Simple JSON-backed store that accumulates findings across scans. Keyed by
target host. When Brain starts scanning a target it has seen before, it can
load its own prior findings as context ("last time on this host I found X,
let me verify those still exist and hunt for new ones").

Phase B first step toward the full episodic memory that Phase C will build
out into a proper vector DB.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

# KB location — data dir at repo root (gitignored for privacy)
_KB_PATH = Path(__file__).parent.parent.parent.parent.parent / "data" / "scan_kb.json"


def _ensure_kb_dir() -> None:
    _KB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load_kb() -> dict[str, Any]:
    if not _KB_PATH.exists():
        return {"targets": {}}
    try:
        return json.loads(_KB_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("Failed to load scan KB: %s", e)
        return {"targets": {}}


def _save_kb(kb: dict[str, Any]) -> None:
    _ensure_kb_dir()
    try:
        _KB_PATH.write_text(json.dumps(kb, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save scan KB: %s", e)


def _target_key(url: str) -> str:
    """Normalize target URL to a stable KB key (host+port)."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc or url
    except Exception:
        return url


def record_scan_result(
    target: str,
    findings: list[dict[str, Any]],
    fingerprint: dict[str, Any] | None = None,
) -> None:
    """Append a scan result to the KB. Called by ScanPipelineV2 at scan end."""
    if not findings and not fingerprint:
        return
    kb = _load_kb()
    key = _target_key(target)
    targets = kb.setdefault("targets", {})
    entry = targets.setdefault(key, {"scans": [], "known_findings": []})

    scan = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings_count": len(findings),
        "fingerprint": fingerprint or {},
        "finding_summaries": [
            {
                "severity": f.get("severity"),
                "finding_type": f.get("finding_type"),
                "affected_component": f.get("affected_component"),
                "title": f.get("title", "")[:120],
            }
            for f in findings
        ],
    }
    entry["scans"].append(scan)
    # Keep only the 20 most recent scans per target
    entry["scans"] = entry["scans"][-20:]

    # Maintain a deduped "known_findings" set on (finding_type, component)
    seen = {
        (kf["finding_type"], kf["affected_component"])
        for kf in entry["known_findings"]
    }
    for f in findings:
        fk = (f.get("finding_type", ""), f.get("affected_component", ""))
        if fk not in seen:
            entry["known_findings"].append({
                "finding_type": f.get("finding_type"),
                "affected_component": f.get("affected_component"),
                "severity": f.get("severity"),
                "first_seen": scan["timestamp"],
            })
            seen.add(fk)

    _save_kb(kb)


class QueryScanMemoryTool:
    name = "query_scan_memory"
    description = (
        "Look up what VXIS has previously found on this target (or on other "
        "targets with the same fingerprint). Call this EARLY in a scan — if "
        "the target has been scanned before, you get the prior findings as "
        "context: verify they still exist, then hunt for new ones. "
        "Cross-scan learning: VXIS gets smarter each time it runs."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL (same format as fingerprint_target).",
            },
        },
        "required": ["url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        url = str(kwargs.get("url", "")).strip()
        if not url:
            return ToolResult(
                ok=False,
                summary="query_scan_memory: url is required",
                error="missing_url",
            )

        kb = _load_kb()
        key = _target_key(url)
        entry = kb.get("targets", {}).get(key)

        if not entry:
            return ToolResult(
                ok=True,
                data={"target_known": False, "scans": [], "known_findings": []},
                summary=f"query_scan_memory: no prior scans recorded for {key}. Fresh target.",
            )

        scans = entry.get("scans", [])
        known = entry.get("known_findings", [])

        return ToolResult(
            ok=True,
            data={
                "target_known": True,
                "key": key,
                "prior_scan_count": len(scans),
                "last_scan": scans[-1] if scans else None,
                "known_findings": known[:30],
                "total_unique_findings_ever": len(known),
            },
            summary=(
                f"query_scan_memory: {key} has {len(scans)} prior scan(s), "
                f"{len(known)} unique findings known. Verify these still "
                f"exist and hunt for new ones."
            ),
        )
