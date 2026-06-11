"""Fail-closed enforcement chokepoints (Component P).

Each chokepoint returns a PolicyDecision and treats `policy is None` as
FORBIDDEN — a profile sets strictness but can never substitute for the
chokepoint. Call-site wiring (shell path, block adaptation, findings[]) is
owned by Phase 1.5 / E / V respectively; this module is the primitive.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol

from vxis.agent.policy.scan_policy import ScanPolicy, ceiling_rank

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


def _fingerprint(value: str) -> str:
    """Non-reversible secret fingerprint for safe logging/persistence.

    sha256 digest provides correlation; the last 4 chars are appended ONLY
    for secrets >= 8 chars (where 4 chars is <= half the value) to aid human
    correlation of long tokens. Short secrets get no raw tail so the value is
    never substantially exposed in stored_value.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    last4 = value[-4:] if len(value) >= 8 else ""
    return f"sha256:{digest}:{last4}"


def persist_secret(value: str, policy: ScanPolicy | None) -> PolicyDecision:
    if policy is None:
        return _forbidden("policy is None (fail-closed)")
    if policy.secret_handling == "plaintext-lab":
        return _allow("plaintext-lab", stored_value=value)
    # Any other mode (incl. encrypt-redact) fingerprints — fail-safe default.
    return _allow("fingerprinted", stored_value=_fingerprint(value))


class ScopeLike(Protocol):
    def in_scope(self, host: str) -> bool: ...


class EngagementLike(Protocol):
    def authorized_ceiling(self) -> str: ...


# Actions that require the highest ceiling (full).
_FULL_ONLY_ACTIONS = frozenset({"data_exfiltration", "persistence_install"})


def permit_pivot(
    target_host: str,
    action: str,
    policy: ScanPolicy | None,
    scope: ScopeLike,
    *,
    engagement: EngagementLike | None = None,
) -> PolicyDecision:
    if policy is None:
        return _forbidden("policy is None (fail-closed)")

    # Effective capability = min(profile ceiling, engagement authorization).
    effective = policy.exploitation_ceiling
    if engagement is not None:
        eng_ceiling = engagement.authorized_ceiling()
        if ceiling_rank(eng_ceiling) < ceiling_rank(effective):
            effective = eng_ceiling

    # Pivoting to another host at all requires at least 'lateral'.
    if ceiling_rank(effective) < ceiling_rank("lateral"):
        return _forbidden(f"exploitation_ceiling '{effective}' too low to pivot")

    # Exfil / persist require 'full'.
    if action in _FULL_ONLY_ACTIONS and ceiling_rank(effective) < ceiling_rank("full"):
        return _forbidden(f"action '{action}' requires ceiling 'full' (have '{effective}')")

    # Destination must be in authorized scope (not approval-gated).
    if not scope.in_scope(target_host):
        return _forbidden(f"host '{target_host}' out of authorized scope")

    return _allow(f"pivot '{action}' to '{target_host}' permitted")
