"""Fail-closed enforcement chokepoints (Component P).

Each chokepoint returns a PolicyDecision and treats `policy is None` as
FORBIDDEN — a profile sets strictness but can never substitute for the
chokepoint. Call-site wiring (shell path, block adaptation, findings[]) is
owned by Phase 1.5 / E / V respectively; this module is the primitive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from vxis.agent.policy.scan_policy import ScanPolicy

# ScopeLike / EngagementLike Protocols + permit_pivot/persist_secret land in Tasks 4-5.

# Canonical evasion strategy identifiers. Component E owns the full taxonomy;
# P only needs to know which strategies are evasion-class.
_EVASION_STRATEGIES = frozenset({"ghost", "tor", "proxy_rotation", "source_ip_rotation"})


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    stored_value: str | None = None  # set by persist_secret only

    @property
    def verdict(self) -> Literal["ALLOW", "FORBIDDEN"]:
        return "ALLOW" if self.allowed else "FORBIDDEN"


def _forbidden(reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason=reason)


def _allow(reason: str = "", stored_value: str | None = None) -> PolicyDecision:
    return PolicyDecision(allowed=True, reason=reason, stored_value=stored_value)


def permit_strategy(strategy: str, policy: ScanPolicy | None) -> PolicyDecision:
    if policy is None:
        return _forbidden("policy is None (fail-closed)")
    if strategy.lower() in _EVASION_STRATEGIES and not policy.evasion_allowed:
        return _forbidden(f"evasion strategy '{strategy}' not permitted by policy")
    return _allow()
