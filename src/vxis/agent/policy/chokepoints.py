"""Fail-closed enforcement chokepoints (Component P).

Each chokepoint returns a PolicyDecision and treats `policy is None` as
FORBIDDEN — a profile sets strictness but can never substitute for the
chokepoint. Call-site wiring (shell path, block adaptation, findings[]) is
owned by Phase 1.5 / E / V respectively; this module is the primitive.
"""

from __future__ import annotations

import hashlib
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
