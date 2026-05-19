"""Local per-scan retrospective recorder.

Separate from GitHub Actions growth-loop. This module captures what happened
in a live scan, where the runtime struggled, and which code areas likely need
improvement. The output is intentionally local-first so unattended scans can
leave behind a machine-readable improvement queue for the next coding loop.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vxis.growth.strix_comparison import build_strix_comparison_scorecard

logger = logging.getLogger(__name__)

_RETRO_DIR = Path(".vxis/retrospectives")
_RETRO_INDEX = _RETRO_DIR / "index.jsonl"


def _ensure_dirs() -> None:
    _RETRO_DIR.mkdir(parents=True, exist_ok=True)


def _target_key(url: str) -> str:
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc or url
    except Exception:
        return url


def _tool_timeline(messages: list[dict[str, Any]], *, limit: int = 40) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict) or msg.get("role") != "tool":
            continue
        content = msg.get("content")
        if not isinstance(content, dict):
            continue
        result = content.get("result") or {}
        data = result.get("data") if isinstance(result, dict) else {}
        out.append(
            {
                "iter": msg.get("iter"),
                "tool": content.get("name", ""),
                "ok": bool(result.get("ok")) if isinstance(result, dict) else False,
                "summary": str(result.get("summary", ""))[:240] if isinstance(result, dict) else "",
                "data_flags": sorted(
                    k for k, v in (data.items() if isinstance(data, dict) else []) if isinstance(v, bool) and v
                )[:8],
            }
        )
    return out[-limit:]


def _count_findings_by_type(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("finding_type", "unknown")).lower()
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _improvement_hints(
    *,
    findings: list[dict[str, Any]],
    verdict_counts: dict[str, int],
    review_queue: list[dict[str, Any]],
    branches: list[dict[str, Any]],
    attempt_outcomes: list[dict[str, Any]],
    callback_observations: list[dict[str, Any]],
    retrieval_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    finding_type_counts = _count_findings_by_type(findings)
    error_oracle_count = finding_type_counts.get("error_oracle", 0)
    refuted = int(verdict_counts.get("REFUTED", 0) or 0)
    unconfirmed = int(verdict_counts.get("UNCONFIRMED", 0) or 0)
    open_reviews = [r for r in review_queue if r.get("status") in {"open", "escalated"}]
    active_branches = [b for b in branches if str(b.get("status", "")).lower() not in {"proven", "exhausted", "dead", "blocked"}]
    failed_sandbox = [
        a for a in attempt_outcomes
        if str(a.get("tool", "")) in {"shell_exec", "python_exec"} and str(a.get("status", "")).lower() in {"failed", "blocked"}
    ]

    if error_oracle_count >= 3:
        hints.append({
            "hint_id": "error_oracle_noise",
            "priority": "medium",
            "reason": f"{error_oracle_count} error_oracle findings were recorded; tighten actionable-error heuristics.",
            "suggested_code_areas": [
                "src/vxis/agent/scan_loop.py",
                "src/vxis/agent/tools/verifier_tools.py",
                "src/vxis/agent/skills/enumerate_endpoints.py",
            ],
        })
    if refuted >= 2:
        hints.append({
            "hint_id": "false_positive_pressure",
            "priority": "high",
            "reason": f"{refuted} findings were refuted by verifier gates; upstream auto-promotion or skill evidence is still too loose.",
            "suggested_code_areas": [
                "src/vxis/agent/scan_loop.py",
                "src/vxis/agent/tools/finding_tools.py",
                "src/vxis/agent/tools/verifier_tools.py",
            ],
        })
    if unconfirmed >= 1 or open_reviews:
        hints.append({
            "hint_id": "evidence_gap",
            "priority": "high",
            "reason": f"{unconfirmed} findings were unconfirmed and {len(open_reviews)} review items remain open/escalated.",
            "suggested_code_areas": [
                "src/vxis/agent/skills/",
                "src/vxis/agent/scan_loop.py",
                "src/vxis/agent/tools/verifier_tools.py",
            ],
        })
    if active_branches:
        hints.append({
            "hint_id": "unfinished_branch_pressure",
            "priority": "medium",
            "reason": f"{len(active_branches)} attack branches were still active at scan end or finish rejection time.",
            "suggested_code_areas": [
                "src/vxis/agent/scan_loop.py",
                "src/vxis/agent/brain.py",
            ],
        })
    if failed_sandbox:
        hints.append({
            "hint_id": "sandbox_execution_gap",
            "priority": "medium",
            "reason": f"{len(failed_sandbox)} sandbox actions failed or were blocked; Brain/tool routing may still be wasteful.",
            "suggested_code_areas": [
                "src/vxis/agent/tools/shell_tools.py",
                "src/vxis/agent/tools/python_tools.py",
                "src/vxis/agent/brain.py",
            ],
        })
    if finding_type_counts.get("ssrf", 0) >= 1 and not callback_observations:
        hints.append({
            "hint_id": "callback_visibility_gap",
            "priority": "high",
            "reason": "SSRF-style findings were recorded without callback/internal-reachability artifacts.",
            "suggested_code_areas": [
                "src/vxis/agent/skills/test_ssrf.py",
                "src/vxis/agent/scan_loop.py",
                "src/vxis/pipeline/scan_pipeline_v2.py",
            ],
        })
    if any(
        finding_type_counts.get(ft, 0) > 0
        for ft in ("idor", "broken_access_control", "information_disclosure", "sql_injection")
    ) and not retrieval_observations:
        hints.append({
            "hint_id": "retrieval_trace_gap",
            "priority": "high",
            "reason": "Data-bearing findings were recorded without retrieval/exfil artifacts that show what was actually accessed.",
            "suggested_code_areas": [
                "src/vxis/agent/scan_loop.py",
                "src/vxis/agent/skills/post_auth_enum.py",
                "src/vxis/agent/skills/test_idor.py",
            ],
        })
    if len(findings) >= 2 and not any("chain" in str(r.get("title", "")) or r.get("title") == "needs_chains" for r in review_queue):
        # no-op, chain pressure handled elsewhere
        pass

    return hints


def record_scan_retrospective(
    *,
    scan_id: str,
    target: str,
    findings: list[dict[str, Any]],
    loop_result: dict[str, Any],
    messages: list[dict[str, Any]],
    attack_chains: list[Any] | None = None,
    llm_usage: dict[str, Any] | None = None,
    control_plane: dict[str, Any] | None = None,
) -> Path:
    """Persist a local retrospective JSON and append an index entry."""
    _ensure_dirs()

    verdict_counts = dict(loop_result.get("verdict_counts") or {})
    review_queue = list(loop_result.get("review_queue") or [])
    review_history = list(loop_result.get("review_history") or [])
    branches = list(loop_result.get("branches") or [])
    attempt_outcomes = list(loop_result.get("attempt_outcomes") or [])
    callback_observations = list(loop_result.get("callback_observations") or [])
    retrieval_observations = list(loop_result.get("retrieval_observations") or [])

    payload = {
        "scan_id": scan_id,
        "target": target,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "completed": bool(loop_result.get("completed")),
        "iterations": int(loop_result.get("iterations") or 0),
        "findings_count": len(findings),
        "findings_by_type": _count_findings_by_type(findings),
        "verdict_counts": verdict_counts,
        "review_queue": review_queue,
        "review_history_tail": review_history[-20:],
        "review_history_count": len(review_history),
        "open_review_count": sum(1 for item in review_queue if item.get("status") in {"open", "escalated"}),
        "active_branch_count": sum(
            1
            for branch in branches
            if str(branch.get("status", "")).lower() not in {"proven", "exhausted", "dead", "blocked"}
        ),
        "callback_observation_count": len(callback_observations),
        "retrieval_observation_count": len(retrieval_observations),
        "callback_observations": callback_observations[-10:],
        "retrieval_observations": retrieval_observations[-10:],
        "llm_runtime": {
            "provider": str((llm_usage or {}).get("provider") or ""),
            "model": str((llm_usage or {}).get("model") or ""),
            "discipline_profile": str((control_plane or {}).get("telemetry", {}).get("discipline_profile") or ""),
        },
        "memory_compression": dict((control_plane or {}).get("telemetry", {}).get("memory_compression") or {}),
        "timeline": _tool_timeline(messages),
        "strix_comparison": build_strix_comparison_scorecard(
            findings=findings,
            loop_result=loop_result,
            attack_chains=attack_chains or [],
            llm_usage=llm_usage or {},
            control_plane=control_plane or {},
        ),
        "improvement_hints": _improvement_hints(
            findings=findings,
            verdict_counts=verdict_counts,
            review_queue=review_queue,
            branches=branches,
            attempt_outcomes=attempt_outcomes,
            callback_observations=callback_observations,
            retrieval_observations=retrieval_observations,
        ),
    }

    path = _RETRO_DIR / f"{scan_id}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    with _RETRO_INDEX.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "scan_id": scan_id,
            "target": target,
            "recorded_at": payload["recorded_at"],
            "completed": payload["completed"],
            "findings_count": payload["findings_count"],
            "open_review_count": payload["open_review_count"],
            "hint_ids": [hint["hint_id"] for hint in payload["improvement_hints"]],
            "path": str(path),
        }, ensure_ascii=False) + "\n")

    logger.info("scan retrospective recorded: %s", path)
    return path


def load_latest_target_retrospective(target: str) -> dict[str, Any] | None:
    """Return the newest retrospective JSON for the target, if any."""
    key = _target_key(target)
    if not _RETRO_INDEX.exists():
        return None
    try:
        lines = [line.strip() for line in _RETRO_INDEX.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:
        logger.warning("Failed to read retrospective index: %s", exc)
        return None

    for raw in reversed(lines):
        try:
            row = json.loads(raw)
        except Exception:
            continue
        if _target_key(str(row.get("target", ""))) != key:
            continue
        path = Path(str(row.get("path", "")))
        if not path.exists():
            continue
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load retrospective payload %s: %s", path, exc)
            return None
    return None
