from __future__ import annotations

from datetime import datetime
from typing import Any

from vxis.p1.audit import AuditLog
from vxis.p1.models import Engagement, State, parse_utc_datetime, utc_now_iso
from vxis.p1.resolver import Resolver, resolve_all
from vxis.p1.scope import ScopeDecision, classify


class EnforcementError(Exception):
    def __init__(self, reason: str, *, audit_entry: dict[str, Any] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.audit_entry = audit_entry or {}


def enforce(
    engagement: Engagement,
    *,
    technique: str,
    target: str,
    destructive: bool = False,
    resolver: Resolver,
    audit: AuditLog,
    now: str | datetime | None = None,
    action: str = "",
    evidence_ref: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Authorize a target action and append an audit record for allow/reject."""
    now_iso = _now_iso(now)
    resolved_targets = resolve_all(target, resolver)
    try:
        _validate_engagement_ready(engagement, now_iso)
        _validate_policy(engagement, technique=technique, destructive=destructive)
        _validate_scope(engagement, target=target, resolved_targets=resolved_targets)
    except EnforcementError as exc:
        entry = _append(
            audit,
            engagement,
            technique=technique,
            target=target,
            action=action or technique,
            decision="REJECT",
            ts=now_iso,
            reason=exc.reason,
            resolved_targets=resolved_targets,
            evidence_ref=evidence_ref,
            metadata=metadata,
        )
        exc.audit_entry = entry
        raise
    return _append(
        audit,
        engagement,
        technique=technique,
        target=target,
        action=action or technique,
        decision="ALLOW",
        ts=now_iso,
        reason="",
        resolved_targets=resolved_targets,
        evidence_ref=evidence_ref,
        metadata=metadata,
    )


def assert_engagement_active(engagement: Engagement, *, now: str | datetime | None = None) -> None:
    _validate_engagement_ready(engagement, _now_iso(now))


def _validate_engagement_ready(engagement: Engagement, now_iso: str) -> None:
    if engagement.state is not State.ACTIVE:
        raise EnforcementError(f"engagement not active: {engagement.state.value}")
    if not engagement.attested:
        raise EnforcementError("engagement not attested")
    now_dt = parse_utc_datetime(now_iso)
    if now_dt < parse_utc_datetime(engagement.window.start):
        raise EnforcementError("engagement window has not started")
    if now_dt > parse_utc_datetime(engagement.window.expiry, end_of_day=True):
        raise EnforcementError("engagement window expired")


def _validate_policy(engagement: Engagement, *, technique: str, destructive: bool) -> None:
    allowed = {item.lower() for item in engagement.policy.techniques}
    if technique.lower() not in allowed:
        raise EnforcementError(f"technique '{technique}' not authorized")
    if destructive and not engagement.policy.destructive:
        raise EnforcementError("destructive action blocked by policy")


def _validate_scope(engagement: Engagement, *, target: str, resolved_targets: list[str]) -> None:
    decisions = [(item, classify(item, engagement.scope)) for item in resolved_targets or [target]]
    for item, decision in decisions:
        if decision is ScopeDecision.DENIED:
            raise EnforcementError(f"{item} explicitly excluded")
    if not any(decision is ScopeDecision.ALLOWED for _item, decision in decisions):
        raise EnforcementError(f"{target} out of scope")


def _append(
    audit: AuditLog,
    engagement: Engagement,
    *,
    technique: str,
    target: str,
    action: str,
    decision: str,
    ts: str,
    reason: str,
    resolved_targets: list[str],
    evidence_ref: str,
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    return audit.append(
        ts=ts,
        eng_id=engagement.id,
        operator=engagement.operator,
        action=action,
        target=target,
        technique=technique,
        decision=decision,
        reason=reason,
        resolved_targets=resolved_targets,
        evidence_ref=evidence_ref,
        metadata=metadata or {},
    )


def _now_iso(now: str | datetime | None) -> str:
    if now is None:
        return utc_now_iso()
    if isinstance(now, datetime):
        return parse_utc_datetime(now).strftime("%Y-%m-%dT%H:%M:%SZ")
    return parse_utc_datetime(now).strftime("%Y-%m-%dT%H:%M:%SZ")
