"""Internal self-maturity scorecard for a scan's output.

A stable rubric that scores each scan's output on five dimensions computed from
real run data (findings, chains, control-plane, LLM usage). The goal is to
track "is our depth improving over time?" numerically across runs.

NOTE: this is an INTERNAL self-rubric, not a competitor comparison. An earlier
version hardcoded a fictional "Strix = 100" baseline and emitted overall_gap
into every retrospective; that fabricated number was removed (honesty over
aspiration). Compare scorecards across our own runs, not against a made-up bar.
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


def _clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(upper, value))


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


def build_maturity_scorecard(
    *,
    findings: list[dict[str, Any]],
    loop_result: dict[str, Any],
    attack_chains: list[Any] | None = None,
    llm_usage: dict[str, Any] | None = None,
    control_plane: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score this scan's output on five maturity dimensions (0-100 each).

    Returns ``{"method", "overall", "dimensions": {dim: score}}`` — bare scores,
    no competitor baseline. Track these across our own runs over time.
    """
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
        "method": "self_maturity_rubric_v1",
        "overall": overall,
        "dimensions": dimensions,
    }
