"""Heuristic maturity scorecard for comparing VXIS runtime output to Strix.

This is intentionally a stable rubric rather than a claim of objective truth.
The goal is to record the same dimensions over time so "are we getting closer
to Strix-style depth?" can be tracked numerically instead of by gut feel.
"""
from __future__ import annotations

from typing import Any


_CHAINABLE_TYPES = {
    "weak_auth",
    "information_disclosure",
    "misconfiguration",
    "broken_access_control",
    "idor",
    "sql_injection",
    "xss",
    "ssrf",
    "csrf",
    "command_injection",
    "path_traversal",
    "business_logic",
}

_STRIX_BASELINE = {
    "poc_rigor": 100,
    "chaining_depth": 100,
    "campaign_convergence": 100,
    "autonomy": 100,
    "operator_visibility": 100,
}


def _clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(upper, value))


def _finding_blob(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(key, ""))
        for key in ("finding_type", "title", "description", "impact", "technical_analysis", "poc_description")
    ).lower()


def _score_poc_rigor(findings: list[dict[str, Any]], verdict_counts: dict[str, int]) -> float:
    if not findings:
        return 0.0
    structured = 0
    for finding in findings:
        has_poc = bool(str(finding.get("poc_script_code", "")).strip() or str(finding.get("poc_description", "")).strip())
        has_analysis = bool(str(finding.get("technical_analysis", "")).strip())
        has_evidence = bool(str(finding.get("evidence", "")).strip())
        if has_poc and has_analysis and has_evidence:
            structured += 1
    completeness = structured / max(1, len(findings))
    confirmed = int(verdict_counts.get("CONFIRMED", 0) or 0)
    refuted = int(verdict_counts.get("REFUTED", 0) or 0)
    unconfirmed = int(verdict_counts.get("UNCONFIRMED", 0) or 0)
    score = completeness * 78.0
    score += min(22.0, confirmed * 5.0)
    score -= refuted * 6.0
    score -= unconfirmed * 3.0
    return _clamp(score)


def _score_chaining_depth(findings: list[dict[str, Any]], attack_chains: list[Any]) -> float:
    chainable = [
        finding for finding in findings
        if str(finding.get("finding_type", "")).strip().lower() in _CHAINABLE_TYPES
        and str(finding.get("severity", "low")).strip().lower() in {"critical", "high", "medium"}
    ]
    if not chainable:
        return 0.0
    desired = 1 if len(chainable) < 4 else min(3, max(2, len(chainable) // 3))
    chain_count = len(attack_chains or [])
    coverage = min(1.0, chain_count / max(1, desired))
    crown_count = 0
    for chain in attack_chains or []:
        raw = chain.get("raw", chain) if isinstance(chain, dict) else {}
        if isinstance(raw, dict) and str(raw.get("crown_jewel", "")).strip():
            crown_count += 1
    crown_ratio = crown_count / max(1, chain_count) if chain_count else 0.0
    score = coverage * 72.0 + crown_ratio * 28.0
    return _clamp(score)


def _score_campaign_convergence(
    *,
    completed: bool,
    branches: list[dict[str, Any]],
    review_queue: list[dict[str, Any]],
    control_plane: dict[str, Any] | None,
) -> float:
    if completed:
        return 100.0
    active = [
        branch for branch in branches
        if str(branch.get("status", "")).lower() not in {"proven", "exhausted", "dead", "blocked"}
    ]
    blockers = list((control_plane or {}).get("blocking_branches") or [])
    open_reviews = [
        item for item in review_queue
        if str(item.get("status", "")).lower() in {"open", "escalated"}
    ]
    score = 100.0
    score -= min(45.0, len(active) * 4.5)
    score -= min(35.0, len(blockers) * 8.0)
    score -= min(20.0, len(open_reviews) * 2.5)
    return _clamp(score)


def _score_autonomy(
    *,
    llm_usage: dict[str, Any] | None,
    review_queue: list[dict[str, Any]],
    control_plane: dict[str, Any] | None,
) -> float:
    llm_calls = int((llm_usage or {}).get("llm_calls") or (control_plane or {}).get("telemetry", {}).get("llm_calls") or 0)
    brain_decisions = int((llm_usage or {}).get("brain_decisions") or (control_plane or {}).get("telemetry", {}).get("brain_decisions") or 0)
    blockers = len((control_plane or {}).get("blocking_branches") or [])
    open_reviews = sum(1 for item in review_queue if str(item.get("status", "")).lower() in {"open", "escalated"})
    score = 35.0
    if llm_calls > 0:
        score += min(25.0, llm_calls * 2.5)
    if brain_decisions > 0:
        score += min(20.0, brain_decisions * 2.0)
    score -= min(20.0, blockers * 3.0 + open_reviews * 2.0)
    return _clamp(score)


def _score_operator_visibility(control_plane: dict[str, Any] | None, review_history_count: int) -> float:
    cp = control_plane or {}
    score = 20.0
    if cp.get("focus_branch"):
        score += 15.0
    if cp.get("focus_campaign"):
        score += 22.0
    if cp.get("campaign_groups"):
        score += 18.0
    if cp.get("blocking_branches"):
        score += 12.0
    if cp.get("chain_candidates"):
        score += 8.0
    if review_history_count > 0:
        score += 5.0
    return _clamp(score)


def build_strix_comparison_scorecard(
    *,
    findings: list[dict[str, Any]],
    loop_result: dict[str, Any],
    attack_chains: list[Any] | None = None,
    llm_usage: dict[str, Any] | None = None,
    control_plane: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verdict_counts = dict(loop_result.get("verdict_counts") or {})
    review_queue = list(loop_result.get("review_queue") or [])
    branches = list(loop_result.get("branches") or [])
    review_history = list(loop_result.get("review_history") or [])
    dimensions = {
        "poc_rigor": round(_score_poc_rigor(findings, verdict_counts), 1),
        "chaining_depth": round(_score_chaining_depth(findings, list(attack_chains or [])), 1),
        "campaign_convergence": round(
            _score_campaign_convergence(
                completed=bool(loop_result.get("completed")),
                branches=branches,
                review_queue=review_queue,
                control_plane=control_plane,
            ),
            1,
        ),
        "autonomy": round(
            _score_autonomy(
                llm_usage=llm_usage,
                review_queue=review_queue,
                control_plane=control_plane,
            ),
            1,
        ),
        "operator_visibility": round(
            _score_operator_visibility(control_plane, len(review_history)),
            1,
        ),
    }
    overall = round(sum(dimensions.values()) / max(1, len(dimensions)), 1)
    return {
        "reference": "strix",
        "method": "heuristic_fixed_rubric_v1",
        "overall_vxis": overall,
        "overall_strix": 100.0,
        "overall_gap": round(100.0 - overall, 1),
        "dimensions": {
            key: {
                "vxis": value,
                "strix": _STRIX_BASELINE[key],
                "gap": round(_STRIX_BASELINE[key] - value, 1),
            }
            for key, value in dimensions.items()
        },
    }
