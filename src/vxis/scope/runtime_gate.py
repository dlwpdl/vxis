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
_BARE_TARGET_RE = re.compile(
    r"(?<![@\w.-])("
    r"localhost|"
    r"(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[a-z0-9-]+\.)+[a-z]{2,}"
    r")(?::\d{1,5})?(?:/[^\s'\"<>)]*)?",
    re.IGNORECASE,
)
_NETWORK_HINT_RE = re.compile(
    r"\b(?:curl|wget|nmap|nc|netcat|telnet|ssh|ftp|ffuf|gobuster|nikto|sqlmap|"
    r"httpx|requests|aiohttp|urllib|socket|connect|open_connection)\b",
    re.IGNORECASE,
)
_PYTHON_SYMBOL_TARGET_RE = re.compile(
    r"^(?:socket|requests|httpx|aiohttp|urllib|asyncio)\.[A-Za-z_]\w*$",
    re.IGNORECASE,
)
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


def build_target_scope_enforcer(target: str, *, scope_arg: str | None = None) -> ScopeEnforcer:
    """Load scope for a scan and FAIL-CLOSED inject the target host into
    in_scope_domains when none are configured, so out-of-scope hosts are blocked
    by default."""
    from urllib.parse import urlparse

    from vxis.scope.loader import load_scope

    cfg = load_scope(scope_arg, target)
    if not cfg.in_scope_domains:
        normalized = target if target.startswith(("http://", "https://")) else f"http://{target}"
        host = urlparse(normalized).hostname or ""
        if host:
            cfg.in_scope_domains = [host]
    return ScopeEnforcer(cfg)


def ensure_active_scope(target: str, *, scope_arg: str | None = None) -> bool:
    """Activate a fail-closed scope for *target* ONLY if no ambient scope is active.

    Returns True if this call activated the scope (caller owns teardown), False if a
    scope was already active (caller must NOT clear it — its owner will).
    """
    if _ACTIVE.get() is not None:
        return False
    set_active_scope(build_target_scope_enforcer(target, scope_arg=scope_arg))
    return True


def enforce_scope_invocation(tool_name: str, args: dict[str, Any]) -> ScopeGateDecision | None:
    """Return None when no scope is active or the tool is offline; otherwise allow/block."""
    enforcer = _ACTIVE.get()
    if enforcer is None:
        return None
    # Lazy import on purpose: importing vxis.agent.egress_contract at module top
    # would execute vxis.agent.__init__ during vxis.scope import and can create a
    # load-time circular import. Keep this local — do not hoist to module scope.
    from vxis.agent.egress_contract import TOOL_TARGET_EGRESS

    contract = TOOL_TARGET_EGRESS.get(tool_name)
    if contract is not None and not contract.target_facing:
        return None

    urls = _extract_urls(tool_name, args)
    if not urls:
        if tool_name in {"shell_exec", "python_exec"} and _payload_looks_networked(args):
            return ScopeGateDecision(
                allowed=False,
                reason=f"{tool_name} contains network tooling but no parseable URL/host target",
                policy="deny",
            )
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
    """Pull candidate target URLs from tool args, in priority order, de-duplicated.

    Priority: explicit ``p1_target`` (str or list) → first present of
    ``url``/``target_url``/``base_url``/``target`` → any inline URLs found in a
    ``command``/``code`` payload.
    """
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
        if tool_name in {"shell_exec", "python_exec"} and _NETWORK_HINT_RE.search(text):
            out.extend(_BARE_TARGET_RE.findall(text))
    seen: set[str] = set()
    deduped: list[str] = []
    for u in out:
        clean = str(u).strip().rstrip("),.;")
        if tool_name == "python_exec" and _PYTHON_SYMBOL_TARGET_RE.match(clean):
            continue
        if clean and clean not in seen:
            seen.add(clean)
            deduped.append(clean)
    return deduped


def _payload_looks_networked(args: dict[str, Any]) -> bool:
    return bool(_NETWORK_HINT_RE.search(str(args.get("command") or args.get("code") or "")))
