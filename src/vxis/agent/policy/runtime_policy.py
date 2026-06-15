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


# NOW-2/2d (F2): run_skill attack-template governance. Passive recon/audit skills
# (read-only) are always allowed; everything else (incl. unknown/improvised names)
# is treated as active exploitation and requires exploitation_ceiling >= 'lateral'.
_PASSIVE_SKILLS = frozenset(
    {
        # web recon / read-only checks (GET-only; no payloads, no state change)
        "enumerate_endpoints", "test_sensitive_files", "test_misconfig",
        "test_crypto", "test_infra",
        # macOS desktop static audits (read-only inspection)
        "test_local_storage_secrets", "test_electron_misconfig", "test_signature_audit",
        "test_entitlement_audit", "test_dylib_hijack", "test_deeplink_abuse",
        "test_ipc_injection", "test_binary_protections",
    }
)


def skill_blocked_by_ceiling(skill_name: str, policy: ScanPolicy | None) -> bool:
    """True when an ACTIVE policy's exploitation ceiling forbids running this skill.

    Active (exploitation/mutating) skills require exploitation_ceiling >= 'lateral';
    passive recon/audit skills are always allowed. Fail-closed: an unknown/unlisted
    skill is treated as active. policy None → not blocked (legacy / ceiling off).
    Pass the alias-RESOLVED skill name (skill_runner normalizes before calling).
    """
    if policy is None:
        return False
    if skill_name.strip().lower() in _PASSIVE_SKILLS:
        return False
    return ceiling_rank(policy.exploitation_ceiling) < ceiling_rank("lateral")
