"""Standard-path scope runtime gate | 표준 경로 스코프 런타임 게이트.

Mirrors p1.runtime_gate but injects an ambient ScopeEnforcer via ContextVar so
EVERY target-facing tool call through ToolRegistry.dispatch is scope/approval
checked even when no P1 engagement is active. Fail-closed.
"""
from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from vxis.scope.enforcer import ScopeEnforcer

_ACTIVE: ContextVar[ScopeEnforcer | None] = ContextVar("vxis_active_scope_enforcer", default=None)
_APPROVE: ContextVar[bool] = ContextVar("vxis_scope_approve_destructive", default=False)

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_TARGET_KEYS = ("url", "target_url", "base_url", "target")


@dataclass(frozen=True)
class ScopeGateDecision:
    allowed: bool
    reason: str = ""
    policy: str = ""
    requires_approval: bool = False


def set_active_scope(enforcer: ScopeEnforcer, *, approve_destructive: bool = False) -> None:
    _ACTIVE.set(enforcer)
    _APPROVE.set(bool(approve_destructive))


def clear_active_scope() -> None:
    _ACTIVE.set(None)
    _APPROVE.set(False)


def enforce_scope_invocation(tool_name: str, args: dict[str, Any]) -> ScopeGateDecision | None:
    """Return None when no scope is active or the tool is offline; otherwise allow/block."""
    enforcer = _ACTIVE.get()
    if enforcer is None:
        return None
    from vxis.agent.egress_contract import TOOL_TARGET_EGRESS

    contract = TOOL_TARGET_EGRESS.get(tool_name)
    if contract is not None and not contract.target_facing:
        return None

    urls = _extract_urls(tool_name, args)
    if not urls:
        return None
    method = str(args.get("method") or "GET")
    body = args.get("body") if isinstance(args.get("body"), dict) else None

    for url in urls:
        result = enforcer.check_action(method, url, body)
        if result.allowed:
            continue
        if result.requires_approval and _APPROVE.get():
            continue
        return ScopeGateDecision(
            allowed=False,
            reason=result.reason,
            policy=result.policy.value,
            requires_approval=result.requires_approval,
        )
    return ScopeGateDecision(allowed=True)


def _extract_urls(tool_name: str, args: dict[str, Any]) -> list[str]:
    explicit = args.get("p1_target")
    out: list[str] = []
    if isinstance(explicit, str) and explicit.strip():
        out.append(explicit.strip())
    elif isinstance(explicit, list):
        out.extend(str(x).strip() for x in explicit if str(x).strip())
    for key in _TARGET_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
            break
    text = str(args.get("command") or args.get("code") or "")
    if text:
        out.extend(_URL_RE.findall(text))
    seen: set[str] = set()
    deduped: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped
