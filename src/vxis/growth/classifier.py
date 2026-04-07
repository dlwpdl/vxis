"""Proposal risk classification|||제안 위험도 분류."""

from __future__ import annotations

from vxis.growth.schemas import Proposal, RiskLevel

CHANGE_TYPE_RISK: dict[str, RiskLevel] = {
    "vector_add": "low",
    "guide_advice_append": "low",
    "kb_pattern_add": "low",
    "wordlist_expand": "low",
    "waf_variant_add": "low",
    "actor_profile_update": "low",
    "phase_reorder": "high",
    "scope_change": "critical",
    "new_phase": "high",
}

_RISK_LADDER: dict[RiskLevel, RiskLevel] = {
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


def classify_proposal(proposal: Proposal) -> Proposal:
    """Assign risk based on change type + confidence|||변경 유형/신뢰도 기반 위험도 부여."""
    base_risk: RiskLevel = CHANGE_TYPE_RISK.get(proposal.change_type, "high")
    if proposal.confidence < 0.5:
        base_risk = _RISK_LADDER.get(base_risk, "critical")
    proposal.risk = base_risk
    return proposal


def should_auto_apply(proposal: Proposal, config: dict) -> bool:
    """Decide auto-apply eligibility|||자동 적용 적격 여부."""
    if config["apply"]["dry_run"]:
        return False
    threshold = float(config["apply"]["auto_apply_threshold"])
    if proposal.confidence < threshold:
        return False
    if proposal.risk in ("high", "critical"):
        return False
    return True
