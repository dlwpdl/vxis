"""Bridge legacy scan memory shapes into PTI dossiers.

Phase 0 keeps the old AgentMemory and scan_kb stores alive for rollback, while
PTI shadows them behind VXIS_V3_MEMORY. This module owns the field-level
mapping and the PTI-backed read views used during the parity window.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from vxis.agent.memory import ScanMemory
from vxis.agent.tool_registry import ToolResult
from vxis.pti.hashing import target_hash_for_url
from vxis.pti.models import (
    AuthoredTool,
    Dossier,
    FindingHistoryEntry,
    StackEntry,
)


def pti_root_from_env(default: str | Path = "data/pti") -> Path:
    """Resolve the PTI root used by Phase 0 memory shadowing."""
    return Path(os.environ.get("VXIS_PTI_ROOT") or os.environ.get("VXIS_PTI_DIR") or default)


def scan_memory_to_dossier_facts(
    mem: ScanMemory,
    scan_id: str = "legacy-import",
) -> Dossier:
    """Map every legacy ScanMemory field onto PTI Dossier facts."""
    target_hash = target_hash_for_url(mem.target)
    stack = [
        StackEntry(
            tech=str(tech),
            confidence=0.5,
            first_seen_scan=scan_id,
            last_seen_scan=scan_id,
            evidence=["legacy AgentMemory tech_stack"],
        )
        for tech in mem.tech_stack
        if str(tech).strip()
    ]
    findings_history = [
        FindingHistoryEntry(
            finding_id=f"{scan_id}-{index}",
            finding_type=str(item.get("type") or item.get("finding_type") or "unknown"),
            surface_id="legacy",
            status="unknown",
            first_seen_scan=scan_id,
            last_verified_scan=scan_id,
            severity=str(item.get("severity") or ""),
            title=str(item.get("title") or ""),
        )
        for index, item in enumerate(mem.findings_summary)
        if isinstance(item, dict)
    ]
    authored_tools = [
        AuthoredTool(
            name=str(tool),
            purpose="legacy-effective-tool",
            script_path="",
            created_scan=scan_id,
            last_used_scan=scan_id,
            success_count=1,
            fail_count=0,
        )
        for tool in mem.effective_tools
        if str(tool).strip()
    ]
    authored_tools.extend(
        AuthoredTool(
            name=str(tool),
            purpose="legacy-ineffective-tool",
            script_path="",
            created_scan=scan_id,
            last_used_scan=scan_id,
            success_count=0,
            fail_count=1,
        )
        for tool in mem.ineffective_tools
        if str(tool).strip()
    )
    return Dossier(
        target_hash=target_hash,
        target_url=mem.target,
        scan_ids=[scan_id],
        stack=stack,
        findings_history=findings_history,
        authored_tools=authored_tools,
        legacy_total_findings=int(mem.total_findings or 0),
        legacy_scan_date=str(mem.scan_date or ""),
    )


def merge_scan_memory_into_dossier(dossier: Dossier, mem: ScanMemory, scan_id: str) -> Dossier:
    """Upsert a legacy ScanMemory projection into an existing dossier."""
    incoming = scan_memory_to_dossier_facts(mem, scan_id=scan_id)
    if scan_id not in dossier.scan_ids:
        dossier.scan_ids.append(scan_id)

    existing_stack = {item.tech.lower(): item for item in dossier.stack}
    for item in incoming.stack:
        current = existing_stack.get(item.tech.lower())
        if current is None:
            dossier.stack.append(item)
        else:
            current.last_seen_scan = scan_id
            current.confidence = max(current.confidence, item.confidence)
            for evidence in item.evidence:
                if evidence not in current.evidence:
                    current.evidence.append(evidence)

    existing_findings = {
        (item.finding_type, item.surface_id, getattr(item, "title", "")): item
        for item in dossier.findings_history
    }
    for item in incoming.findings_history:
        key = (item.finding_type, item.surface_id, getattr(item, "title", ""))
        current = existing_findings.get(key)
        if current is None:
            dossier.findings_history.append(item)
        else:
            current.last_verified_scan = scan_id

    existing_tools = {item.name: item for item in dossier.authored_tools}
    for item in incoming.authored_tools:
        current = existing_tools.get(item.name)
        if current is None:
            dossier.authored_tools.append(item)
        else:
            current.last_used_scan = scan_id
            current.success_count += item.success_count
            current.fail_count += item.fail_count
    return dossier


def persist_scan_memory_to_pti(
    mem: ScanMemory,
    *,
    root: str | Path | None = None,
    scan_id: str = "legacy-import",
) -> Path:
    """Persist one ScanMemory into PTI using idempotent-ish field upserts."""
    from vxis.pti.store import PTIStore

    store = PTIStore(root=root or pti_root_from_env())
    try:
        dossier = store.load_for_target(mem.target, create=False)
    except FileNotFoundError:
        dossier = scan_memory_to_dossier_facts(mem, scan_id=scan_id)
    else:
        dossier = merge_scan_memory_into_dossier(dossier, mem, scan_id=scan_id)
    return store.persist(dossier)


def recall_context_from_pti(
    target_url: str,
    tech_stack: list[str] | None = None,
    root: str | Path | None = None,
) -> str:
    """PTI-backed equivalent of AgentMemory.recall_similar -> format_memory_context."""
    from vxis.pti.store import PTIStore

    store = PTIStore(root=root or pti_root_from_env())
    try:
        dossier = store.load_for_target(target_url, create=False)
    except FileNotFoundError:
        return ""

    query_tech = {str(item).lower() for item in (tech_stack or []) if str(item).strip()}
    stack = [item.tech for item in dossier.stack]
    if query_tech and not (query_tech & {item.lower() for item in stack}):
        return ""

    lines = ["## 과거 스캔 경험", ""]
    tech_label = ", ".join(stack[:4]) if stack else "유사 환경"
    scan_count = max(1, len(dossier.scan_ids))
    lines.append(f"비슷한 타겟 ({tech_label}) 스캔 {scan_count}회:")

    effective = [item for item in dossier.authored_tools if item.success_count > 0]
    weak = [item for item in dossier.authored_tools if item.success_count <= 0]
    for tool in effective[:8]:
        examples = _finding_type_examples(dossier, limit=2)
        example_text = f" ({', '.join(examples)})" if examples else ""
        lines.append(f"- {tool.name}: 평균 1.0건 발견{example_text}")
    for tool in weak[:8]:
        lines.append(f"- {tool.name}: 주로 발견 없음")

    if effective or weak:
        parts: list[str] = []
        if effective:
            parts.append(f"{', '.join(item.name for item in effective[:3])} 우선 실행")
        if weak:
            parts.append(f"{weak[0].name}은 top-100으로 빠르게")
        lines.append("")
        lines.append("→ 추천: " + " / ".join(parts))

    if dossier.findings_history and not effective:
        examples = ", ".join(_finding_type_examples(dossier, limit=4))
        lines.append(f"- prior findings: {examples}")
    return "\n".join(lines)


def query_scan_memory_view(
    *,
    url: str,
    stack_hint: str = "",
    root: str | Path | None = None,
) -> ToolResult:
    """Return the query_scan_memory ToolResult shape backed by PTI."""
    from vxis.pti.store import PTIStore

    store = PTIStore(root=root or pti_root_from_env())
    key = _target_key(url)
    try:
        dossier = store.load_for_target(url, create=False)
    except FileNotFoundError:
        return ToolResult(
            ok=True,
            data=_empty_query_memory_data(key),
            summary=f"query_scan_memory: no prior scans recorded for {key}. Fresh target.",
        )

    known_findings = [_finding_history_to_memory_dict(item) for item in dossier.findings_history]
    aggregated = list(known_findings)
    scans = [
        {
            "scan_id": scan_id,
            "target": dossier.target_url,
            "fingerprint": {
                "recommended_playbooks": [item.tech for item in dossier.stack],
            },
        }
        for scan_id in dossier.scan_ids
    ]
    successful = [
        {
            "tool": item.name,
            "success_count": item.success_count,
            "fail_count": item.fail_count,
            "purpose": item.purpose,
        }
        for item in dossier.authored_tools
        if item.success_count > 0
    ]
    data = {
        "target_known": True,
        "key": key,
        "scans": scans,
        "prior_scan_count": len(scans),
        "last_scan": scans[-1] if scans else None,
        "known_findings": known_findings[:30],
        "aggregated_findings": aggregated[:50],
        "refuted_patterns": [],
        "successful_tactics": successful[:10],
        "branch_leads": [],
        "total_unique_findings_ever": len(known_findings),
        "cross_target_findings": _cross_target_findings(store, dossier, stack_hint),
        "stack_hint": stack_hint or None,
    }
    summary_parts = [
        f"{key} has {len(scans)} prior scan(s), {len(known_findings)} unique findings known"
    ]
    if data["cross_target_findings"]:
        summary_parts.append(
            f"{len(data['cross_target_findings'])} findings from other {stack_hint} targets as cross-stack context"
        )
    return ToolResult(
        ok=True,
        data=data,
        summary="query_scan_memory: "
        + ". ".join(summary_parts)
        + ". Verify these still exist and hunt for new ones.",
    )


def _finding_type_examples(dossier: Dossier, *, limit: int) -> list[str]:
    values: list[str] = []
    for item in dossier.findings_history:
        value = str(item.finding_type or "").strip()
        if value and value not in values:
            values.append(value)
        if len(values) >= limit:
            break
    return values


def _finding_history_to_memory_dict(item: FindingHistoryEntry) -> dict[str, Any]:
    title = str(getattr(item, "title", "") or "")
    severity = str(getattr(item, "severity", "") or "")
    return {
        "finding_type": item.finding_type,
        "affected_component": item.surface_id,
        "severity": severity,
        "title": title,
        "first_seen": item.first_seen_scan,
        "last_seen": item.last_verified_scan,
    }


def _empty_query_memory_data(key: str) -> dict[str, Any]:
    return {
        "target_known": False,
        "key": key,
        "scans": [],
        "known_findings": [],
        "aggregated_findings": [],
        "refuted_patterns": [],
        "successful_tactics": [],
        "branch_leads": [],
        "cross_target_findings": [],
    }


def _cross_target_findings(
    store: Any,
    dossier: Dossier,
    stack_hint: str,
) -> list[dict[str, Any]]:
    hint = str(stack_hint or "").strip().lower()
    if not hint:
        return []
    root = Path(store.root)
    out: list[dict[str, Any]] = []
    for path in root.glob("*/dossier.yaml"):
        try:
            other = store.load(path.parent.name, create=False)
        except Exception:
            continue
        if other.target_hash == dossier.target_hash:
            continue
        stack = {item.tech.lower() for item in other.stack}
        if hint not in stack:
            continue
        for finding in other.findings_history[:5]:
            out.append(
                {
                    "source_target": other.target_hash,
                    "finding_type": finding.finding_type,
                    "affected_component": finding.surface_id,
                    "severity": str(getattr(finding, "severity", "") or ""),
                }
            )
    return out[:20]


def _target_key(url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return (parsed.netloc or parsed.path or url).lower().strip().rstrip("/")
