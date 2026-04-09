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
            "stack_hint": {
                "type": "string",
                "description": (
                    "Optional stack name (e.g. 'spring_boot', 'express_node_spa') "
                    "from fingerprint_target.recommended_playbooks[0]. When "
                    "provided, the tool ALSO returns findings from other targets "
                    "of the same stack as cross-stack learning context."
                ),
            },
        },
        "required": ["url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        url = str(kwargs.get("url", "")).strip()
        stack_hint = str(kwargs.get("stack_hint", "")).strip().lower()
        if not url:
            return ToolResult(
                ok=False,
                summary="query_scan_memory: url is required",
                error="missing_url",
            )

        kb = _load_kb()
        key = _target_key(url)
        targets = kb.get("targets", {})
        entry = targets.get(key)

        # Exact-target results
        exact_findings: list[dict[str, Any]] = []
        prior_scans = 0
        if entry:
            prior_scans = len(entry.get("scans", []))
            exact_findings = entry.get("known_findings", [])

        # Phase B cross-target learning: if caller passes a stack_hint (e.g.
        # "spring_boot"), find other targets with the same stack fingerprint
        # and surface their findings as cross-target context.
        cross_target: list[dict[str, Any]] = []
        if stack_hint:
            for other_key, other_entry in targets.items():
                if other_key == key:
                    continue
                other_scans = other_entry.get("scans", [])
                if not other_scans:
                    continue
                # Check the last scan's fingerprint for the stack
                last_fp = other_scans[-1].get("fingerprint") or {}
                recommended = last_fp.get("recommended_playbooks") or []
                if stack_hint in [str(r).lower() for r in recommended]:
                    for kf in other_entry.get("known_findings", [])[:5]:
                        cross_target.append({
                            "source_target": other_key,
                            "finding_type": kf.get("finding_type"),
                            "affected_component": kf.get("affected_component"),
                            "severity": kf.get("severity"),
                        })

        if not entry and not cross_target:
            return ToolResult(
                ok=True,
                data={
                    "target_known": False,
                    "scans": [],
                    "known_findings": [],
                    "cross_target_findings": [],
                },
                summary=f"query_scan_memory: no prior scans recorded for {key}. Fresh target.",
            )

        total_unique = len(exact_findings)
        summary_parts = []
        if entry:
            summary_parts.append(
                f"{key} has {prior_scans} prior scan(s), {total_unique} unique findings known"
            )
        if cross_target:
            summary_parts.append(
                f"{len(cross_target)} findings from other {stack_hint} targets as cross-stack context"
            )

        return ToolResult(
            ok=True,
            data={
                "target_known": entry is not None,
                "key": key,
                "prior_scan_count": prior_scans,
                "last_scan": entry["scans"][-1] if entry and entry.get("scans") else None,
                "known_findings": exact_findings[:30],
                "total_unique_findings_ever": total_unique,
                "cross_target_findings": cross_target[:20],
                "stack_hint": stack_hint or None,
            },
            summary="query_scan_memory: " + ". ".join(summary_parts)
            + ". Verify these still exist and hunt for new ones."
            if summary_parts
            else f"query_scan_memory: no prior data for {key}.",
        )
