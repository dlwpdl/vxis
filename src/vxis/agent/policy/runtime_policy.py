"""Ambient ScanPolicy for the per-scan run (NOW-2 foundation).

Mirrors scope/runtime_gate's ContextVar pattern so loop-driven tools — dispatched
through tool_registry with no ctx/loop access — can read the active capability
ceiling. Fail-closed by omission: when no policy is set the default is None and
every consumer treats None as "ceiling off → legacy behavior" (the enforcement
rides the same VXIS_V3_POLICY flag that attaches ctx.policy), matching the P1 and
scope gates which enforce only when configured. A ContextVar keeps concurrent
scans isolated.
"""
from __future__ import annotations

from contextvars import ContextVar, Token

from vxis.agent.policy.scan_policy import ScanPolicy, ceiling_rank

_ACTIVE_POLICY: ContextVar[ScanPolicy | None] = ContextVar(
    "vxis_active_scan_policy", default=None
)

# Exploitation primitives: arbitrary shell / code execution. Require ceiling
# >= 'lateral'; below that (none / read-only) they are refused at dispatch.
_EXPLOITATION_TOOLS = frozenset({"shell_exec", "python_exec"})


def set_active_policy(policy: ScanPolicy | None) -> Token:
    """Set the per-context active ScanPolicy; returns a reset token."""
    return _ACTIVE_POLICY.set(policy)


def get_active_policy() -> ScanPolicy | None:
    return _ACTIVE_POLICY.get()


def clear_active_policy(token: Token | None = None) -> None:
    """Clear the active policy. Resets to the prior value if a token is given,
    otherwise sets None (safe for non-nested top-level scan runs)."""
    if token is not None:
        try:
            _ACTIVE_POLICY.reset(token)
            return
        except (ValueError, LookupError):
            pass
    _ACTIVE_POLICY.set(None)


def tool_blocked_by_ceiling(tool_name: str, policy: ScanPolicy | None) -> bool:
    """True when an ACTIVE policy's exploitation ceiling forbids this tool.

    shell_exec / python_exec (arbitrary exploitation primitives) require
    exploitation_ceiling >= 'lateral'; at none/read-only they are blocked.
    policy None → not blocked (ceiling off / legacy).
    """
    if policy is None or tool_name not in _EXPLOITATION_TOOLS:
        return False
    return ceiling_rank(policy.exploitation_ceiling) < ceiling_rank("lateral")
