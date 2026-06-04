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
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

# KB location — data dir at repo root (gitignored for privacy)
_KB_PATH = Path(__file__).parent.parent.parent.parent.parent / "data" / "scan_kb.json"


def _canonical_finding_type(value: str) -> str:
    try:
        from vxis.agent.tools.finding_tools import _canonical_finding_type as _canonical
        return _canonical(value)
    except Exception:
        return str(value or "").lower().strip()


def _base_component(component: str) -> str:
    import re
    from urllib.parse import urlparse

    try:
        parsed = urlparse(component)
        path = parsed.path or component
        if parsed.fragment:
            path = f"{path}#{parsed.fragment}"
    except Exception:
        path = component
    path = str(path).lower().strip().rstrip("/")
    path = path.split("?")[0]
    path = re.sub(r"/\d+(/|$)", "/", path).rstrip("/")
    if path.startswith("/.git/"):
        return "/.git"
    return path


def _finding_memory_key(finding_type: str, affected_component: str) -> str:
    return f"{_canonical_finding_type(finding_type)}::{_base_component(affected_component)}"


def _is_soft_refutation_reason(reasoning: str) -> bool:
    blob = str(reasoning or "").lower()
    soft_markers = (
        "thin_evidence",
        "incomplete high-severity report contract",
        "poc lacks attempt/result transcript",
        "gather raw request/response transcript",
        "missing structured poc",
    )
    return any(marker in blob for marker in soft_markers)


def _filtered_refuted_patterns(items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for item in list(items or []):
        if not isinstance(item, dict):
            continue
        if _is_soft_refutation_reason(str(item.get("reasoning", ""))):
            continue
        filtered.append(item)
    return filtered


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
        "info": 1,
    }.get(str(severity or "").lower().strip(), 0)


def _snapshot_finding(finding: dict[str, Any], *, timestamp: str, scan_id: str = "") -> dict[str, Any]:
    canonical_type = _canonical_finding_type(str(finding.get("finding_type", "")))
    affected_component = str(finding.get("affected_component", ""))
    return {
        "canonical_key": _finding_memory_key(canonical_type, affected_component),
        "finding_type": canonical_type,
        "raw_finding_type": str(finding.get("finding_type", ""))[:80],
        "affected_component": affected_component[:240],
        "component_base": _base_component(affected_component)[:240],
        "severity": str(finding.get("severity", ""))[:32],
        "title": str(finding.get("title", ""))[:160],
        "description": str(finding.get("description", ""))[:240],
        "first_seen": timestamp,
        "last_seen": timestamp,
        "occurrences": 1,
        "source_scan_ids": [scan_id] if scan_id else [],
        "variant_titles": [str(finding.get("title", ""))[:160]] if finding.get("title") else [],
        "variant_types": [str(finding.get("finding_type", ""))[:80]] if finding.get("finding_type") else [],
    }


def _merge_aggregated_findings(
    existing: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    timestamp: str,
    scan_id: str = "",
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in existing:
        if not isinstance(item, dict):
            continue
        key = _finding_memory_key(
            str(item.get("finding_type", "")),
            str(item.get("affected_component", "")),
        )
        if not key:
            continue
        clone = dict(item)
        clone["canonical_key"] = key
        clone["component_base"] = _base_component(str(item.get("affected_component", "")))[:240]
        merged[key] = clone

    for finding in findings:
        snapshot = _snapshot_finding(finding, timestamp=timestamp, scan_id=scan_id)
        key = snapshot["canonical_key"]
        current = merged.get(key)
        if current is None:
            merged[key] = snapshot
            continue
        current["last_seen"] = timestamp
        current["occurrences"] = int(current.get("occurrences", 1) or 1) + 1
        if _severity_rank(snapshot["severity"]) > _severity_rank(str(current.get("severity", ""))):
            current["severity"] = snapshot["severity"]
            current["title"] = snapshot["title"]
            current["description"] = snapshot["description"]
            current["raw_finding_type"] = snapshot["raw_finding_type"]
        if scan_id:
            scan_ids = list(current.get("source_scan_ids") or [])
            if scan_id not in scan_ids:
                scan_ids.append(scan_id)
            current["source_scan_ids"] = scan_ids[-12:]
        titles = list(current.get("variant_titles") or [])
        if snapshot["title"] and snapshot["title"] not in titles:
            titles.append(snapshot["title"])
        current["variant_titles"] = titles[-12:]
        types = list(current.get("variant_types") or [])
        if snapshot["raw_finding_type"] and snapshot["raw_finding_type"] not in types:
            types.append(snapshot["raw_finding_type"])
        current["variant_types"] = types[-12:]

    return sorted(
        merged.values(),
        key=lambda item: (-_severity_rank(str(item.get("severity", ""))), str(item.get("title", ""))),
    )[:100]


def _scan_findings_for_rebuild(scan: dict[str, Any]) -> list[dict[str, Any]]:
    snapshots = list(scan.get("findings_snapshot") or [])
    if snapshots:
        rebuilt: list[dict[str, Any]] = []
        for item in snapshots:
            if not isinstance(item, dict):
                continue
            rebuilt.append({
                "finding_type": str(item.get("raw_finding_type") or item.get("finding_type") or ""),
                "affected_component": str(item.get("affected_component", "")),
                "severity": str(item.get("severity", "")),
                "title": str(item.get("title", "")),
                "description": str(item.get("description", "")),
            })
        return rebuilt
    summaries = list(scan.get("finding_summaries") or [])
    rebuilt = []
    for item in summaries:
        if not isinstance(item, dict):
            continue
        rebuilt.append({
            "finding_type": str(item.get("finding_type", "")),
            "affected_component": str(item.get("affected_component", "")),
            "severity": str(item.get("severity", "")),
            "title": str(item.get("title", "")),
            "description": "",
        })
    return rebuilt


def _rebuild_target_memory_entry(entry: dict[str, Any]) -> dict[str, Any]:
    scans = list(entry.get("scans") or [])
    aggregated: list[dict[str, Any]] = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        aggregated = _merge_aggregated_findings(
            aggregated,
            _scan_findings_for_rebuild(scan),
            timestamp=str(scan.get("timestamp", "")) or datetime.now(timezone.utc).isoformat(),
            scan_id=str(scan.get("scan_id", "")),
        )
    aggregated = _prune_low_confidence_aggregates(aggregated)
    entry["aggregated_findings"] = aggregated
    entry["known_findings"] = [
        {
            "finding_type": item.get("finding_type"),
            "affected_component": item.get("affected_component"),
            "severity": item.get("severity"),
            "title": item.get("title", ""),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "canonical_key": item.get("canonical_key", ""),
            "occurrences": item.get("occurrences", 1),
        }
        for item in aggregated
    ]
    normalized_refuted: list[dict[str, Any]] = []
    for item in list(entry.get("refuted_patterns") or []):
        if not isinstance(item, dict):
            continue
        normalized_refuted.append({
            **item,
            "finding_type": _canonical_finding_type(str(item.get("finding_type", ""))),
            "affected_component": str(item.get("affected_component", ""))[:240],
        })
    entry["refuted_patterns"] = normalized_refuted[-50:]
    normalized_tactics: list[dict[str, Any]] = []
    for item in list(entry.get("successful_tactics") or []):
        if not isinstance(item, dict):
            continue
        normalized_tactics.append({
            **item,
            "finding_type": _canonical_finding_type(str(item.get("finding_type", ""))),
            "affected_component": str(item.get("affected_component", ""))[:240],
        })
    entry["successful_tactics"] = normalized_tactics[-50:]
    return entry


def _parse_iso8601(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def _prune_low_confidence_aggregates(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop stale one-off noisy findings that never reappeared after stricter gates."""
    noisy_types = {"nosql", "ssti", "xss"}
    now = datetime.now(timezone.utc)
    kept: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        finding_type = _canonical_finding_type(str(item.get("finding_type", "")))
        occurrences = int(item.get("occurrences", 0) or 0)
        severity = str(item.get("severity", "")).lower().strip()
        last_seen = _parse_iso8601(str(item.get("last_seen", "")))
        age_days = None
        if last_seen is not None:
            age_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)
        if (
            finding_type in noisy_types
            and occurrences <= 1
            and severity in {"medium", "low", "informational", "info"}
            and (age_days is None or age_days >= 1.0)
        ):
            continue
        kept.append(item)
    return kept


def _ensure_kb_dir() -> None:
    _KB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load_kb() -> dict[str, Any]:
    if not _KB_PATH.exists():
        return {"targets": {}}
    try:
        kb = json.loads(_KB_PATH.read_text(encoding="utf-8"))
        targets = kb.get("targets")
        if isinstance(targets, dict):
            for key, entry in list(targets.items()):
                if isinstance(entry, dict):
                    targets[key] = _rebuild_target_memory_entry(entry)
        return kb
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
    *,
    scan_id: str = "",
    confirmed_findings: list[dict[str, Any]] | None = None,
    refuted_findings: list[dict[str, Any]] | None = None,
    review_history: list[dict[str, Any]] | None = None,
    branches: list[dict[str, Any]] | None = None,
) -> None:
    """Append a scan result to the KB. Called by ScanPipelineV2 at scan end."""
    if not findings and not fingerprint:
        return
    kb = _load_kb()
    key = _target_key(target)
    targets = kb.setdefault("targets", {})
    entry = targets.setdefault(key, {"scans": [], "known_findings": []})
    timestamp = datetime.now(timezone.utc).isoformat()

    scan = {
        "timestamp": timestamp,
        "scan_id": scan_id,
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
        "findings_snapshot": [
            {
                "severity": str(f.get("severity", ""))[:32],
                "finding_type": _canonical_finding_type(str(f.get("finding_type", "")))[:80],
                "raw_finding_type": str(f.get("finding_type", ""))[:80],
                "affected_component": str(f.get("affected_component", ""))[:240],
                "title": str(f.get("title", ""))[:160],
                "canonical_key": _finding_memory_key(
                    str(f.get("finding_type", "")),
                    str(f.get("affected_component", "")),
                ),
            }
            for f in findings
        ],
        "confirmed_findings": list(confirmed_findings or [])[:20],
        "refuted_findings": list(refuted_findings or [])[:20],
        "review_history_tail": list(review_history or [])[-20:],
        "branch_tail": list(branches or [])[-20:],
    }
    entry["scans"].append(scan)
    # Keep only the 20 most recent scans per target
    entry["scans"] = entry["scans"][-20:]

    aggregated_findings = _merge_aggregated_findings(
        list(entry.get("aggregated_findings") or []),
        findings,
        timestamp=timestamp,
        scan_id=scan_id,
    )
    entry["aggregated_findings"] = aggregated_findings
    entry["known_findings"] = [
        {
            "finding_type": item.get("finding_type"),
            "affected_component": item.get("affected_component"),
            "severity": item.get("severity"),
            "title": item.get("title", ""),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "canonical_key": item.get("canonical_key", ""),
            "occurrences": item.get("occurrences", 1),
        }
        for item in aggregated_findings
    ]

    refuted_patterns = entry.setdefault("refuted_patterns", [])
    known_refuted = {
        (str(item.get("finding_type", "")), str(item.get("affected_component", "")))
        for item in refuted_patterns
        if isinstance(item, dict)
    }
    for item in refuted_findings or []:
        if _is_soft_refutation_reason(str(item.get("reasoning", ""))):
            continue
        pair = (
            str(item.get("finding_type", "")),
            str(item.get("affected_component", "")),
        )
        if not pair[0] or pair in known_refuted:
            continue
        refuted_patterns.append({
            "finding_type": _canonical_finding_type(pair[0]),
            "affected_component": pair[1],
            "title": str(item.get("title", ""))[:120],
            "reasoning": str(item.get("reasoning", ""))[:240],
            "last_seen": timestamp,
        })
        known_refuted.add(pair)
    entry["refuted_patterns"] = refuted_patterns[-50:]

    successful_tactics = entry.setdefault("successful_tactics", [])
    seen_tactics = {
        (str(item.get("finding_type", "")), str(item.get("title", "")))
        for item in successful_tactics
        if isinstance(item, dict)
    }
    for item in confirmed_findings or []:
        tactic = (
            str(item.get("finding_type", "")),
            str(item.get("title", ""))[:120],
        )
        if not tactic[0] or tactic in seen_tactics:
            continue
        successful_tactics.append({
            "finding_type": _canonical_finding_type(tactic[0]),
            "title": tactic[1],
            "affected_component": str(item.get("affected_component", ""))[:200],
            "confidence": str(item.get("confidence", ""))[:32],
            "reasoning": str(item.get("reasoning", ""))[:240],
            "last_seen": timestamp,
        })
        seen_tactics.add(tactic)
    entry["successful_tactics"] = successful_tactics[-50:]

    branch_leads = entry.setdefault("branch_leads", [])
    seen_branches = {
        str(item.get("id", ""))
        for item in branch_leads
        if isinstance(item, dict)
    }
    for branch in branches or []:
        if str(branch.get("status", "")).lower() in {"proven", "exhausted", "dead"}:
            continue
        branch_id = str(branch.get("id", ""))
        if not branch_id or branch_id in seen_branches:
            continue
        branch_leads.append({
            "id": branch_id,
            "vector_id": str(branch.get("vector_id", ""))[:80],
            "title": str(branch.get("title", ""))[:160],
            "role": str(branch.get("role", ""))[:40],
            "phase": str(branch.get("phase", ""))[:40],
            "objective": str(branch.get("objective", ""))[:200],
            "next_step": str(branch.get("next_step", ""))[:200],
            "status": str(branch.get("status", ""))[:40],
            "last_seen": timestamp,
        })
        seen_branches.add(branch_id)
    entry["branch_leads"] = branch_leads[-50:]

    _save_kb(kb)


def load_target_memory_profile(target: str) -> dict[str, Any]:
    """Return memory profile for a target for scan bootstrapping."""
    kb = _load_kb()
    key = _target_key(target)
    entry = (kb.get("targets") or {}).get(key) or {}
    scans = list(entry.get("scans") or [])
    return {
        "key": key,
        "target_known": bool(entry),
        "prior_scan_count": len(scans),
        "known_findings": list(entry.get("known_findings") or [])[:30],
        "aggregated_findings": list(entry.get("aggregated_findings") or [])[:50],
        "refuted_patterns": _filtered_refuted_patterns(list(entry.get("refuted_patterns") or []))[:20],
        "successful_tactics": list(entry.get("successful_tactics") or [])[:20],
        "branch_leads": list(entry.get("branch_leads") or [])[:12],
        "last_scan": scans[-1] if scans else None,
    }


def migrate_scan_kb() -> dict[str, int]:
    """Rebuild aggregate memory for all targets using current canonicalization rules."""
    kb = _load_kb()
    targets = kb.get("targets") or {}
    migrated_targets = 0
    for key, entry in list(targets.items()):
        if not isinstance(entry, dict):
            continue
        targets[key] = _rebuild_target_memory_entry(entry)
        migrated_targets += 1
    kb["targets"] = targets
    _save_kb(kb)
    return {"targets": migrated_targets}


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
        if os.environ.get("VXIS_V3_MEMORY", "0") not in {
            "",
            "0",
            "false",
            "False",
            "no",
            "off",
        }:
            from vxis.pti.memory_bridge import query_scan_memory_view

            return query_scan_memory_view(url=url, stack_hint=stack_hint)

        kb = _load_kb()
        key = _target_key(url)
        targets = kb.get("targets", {})
        entry = targets.get(key)

        # Exact-target results
        exact_findings: list[dict[str, Any]] = []
        aggregated_findings: list[dict[str, Any]] = []
        prior_scans = 0
        refuted_patterns: list[dict[str, Any]] = []
        successful_tactics: list[dict[str, Any]] = []
        branch_leads: list[dict[str, Any]] = []
        if entry:
            prior_scans = len(entry.get("scans", []))
            exact_findings = entry.get("known_findings", [])
            aggregated_findings = entry.get("aggregated_findings", [])
            refuted_patterns = _filtered_refuted_patterns(entry.get("refuted_patterns", []))
            successful_tactics = entry.get("successful_tactics", [])
            branch_leads = entry.get("branch_leads", [])

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
                    "aggregated_findings": [],
                    "refuted_patterns": [],
                    "successful_tactics": [],
                    "branch_leads": [],
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
                "aggregated_findings": aggregated_findings[:50],
                "refuted_patterns": refuted_patterns[:10],
                "successful_tactics": successful_tactics[:10],
                "branch_leads": branch_leads[:8],
                "total_unique_findings_ever": total_unique,
                "cross_target_findings": cross_target[:20],
                "stack_hint": stack_hint or None,
            },
            summary="query_scan_memory: " + ". ".join(summary_parts)
            + ". Verify these still exist and hunt for new ones."
            if summary_parts
            else f"query_scan_memory: no prior data for {key}.",
        )
