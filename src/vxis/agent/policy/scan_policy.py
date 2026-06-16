"""ScanPolicy model + profile→policy resolution (Component P).

A ScanPolicy is the *capability* axis (what the profile permits), composed
later with the *authorization* axis (per-engagement) via min(). Immutable:
a resolved policy must not mutate mid-scan.
"""

from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict

from vxis.config.schema import normalize_scan_profile_name

Ceiling = Literal["none", "read-only", "lateral", "full"]

_CEILING_ORDER: dict[str, int] = {"none": 0, "read-only": 1, "lateral": 2, "full": 3}

assert set(_CEILING_ORDER) == set(get_args(Ceiling)), "_CEILING_ORDER out of sync with Ceiling"


def ceiling_rank(ceiling: Ceiling | str) -> int:
    """Ordered rank for min()/comparison. Unknown ceilings rank as the most
    restrictive (0), so a typo can never silently grant capability."""
    return _CEILING_ORDER.get(ceiling, 0)


class ScanPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    exploitation_ceiling: Ceiling
    scope_strictness: Literal["lab-allowlist", "strict-authorized"]
    tenant_isolation: bool
    secret_handling: Literal["plaintext-lab", "encrypt-redact"]
    evasion_allowed: bool
    deferred_mutation_approval: bool


# ---------------------------------------------------------------------------
# Fail-closed default — any None config / empty / unknown profile lands here.
# ---------------------------------------------------------------------------

FAIL_CLOSED_DEFAULT = ScanPolicy(
    exploitation_ceiling="none",
    scope_strictness="strict-authorized",
    tenant_isolation=True,
    secret_handling="encrypt-redact",
    evasion_allowed=False,
    deferred_mutation_approval=True,
)

_PROD_READONLY = ScanPolicy(
    exploitation_ceiling="read-only",
    scope_strictness="strict-authorized",
    tenant_isolation=True,
    secret_handling="encrypt-redact",
    evasion_allowed=False,
    deferred_mutation_approval=True,
)

PROFILE_POLICY_TABLE: dict[str, ScanPolicy] = {
    "crown": ScanPolicy(
        exploitation_ceiling="lateral",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=False,
        deferred_mutation_approval=True,
    ),
    "aggressive": ScanPolicy(
        exploitation_ceiling="full",
        scope_strictness="lab-allowlist",
        tenant_isolation=False,
        secret_handling="plaintext-lab",
        evasion_allowed=True,
        deferred_mutation_approval=False,
    ),
    "pre-investment-dd": ScanPolicy(
        exploitation_ceiling="full",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=True,
        deferred_mutation_approval=True,
    ),
    "p1-adversary-emulation": ScanPolicy(
        exploitation_ceiling="full",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=True,
        deferred_mutation_approval=True,
    ),
    "continuous-devsec": _PROD_READONLY,
    "vc-portfolio-monitor": _PROD_READONLY,
    "remediation-verification": _PROD_READONLY,
    "passive": _PROD_READONLY,
    "standard": _PROD_READONLY,
    "stealth": _PROD_READONLY,
    "compliance-mapping": ScanPolicy(
        exploitation_ceiling="none",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=False,
        deferred_mutation_approval=True,
    ),
}


def attack_level_badge(profile_name: str) -> dict:
    """NOW-3 #2: quantify a profile's attack level for the TUI/dashboard.

    Reads the profile's ScanPolicy straight from PROFILE_POLICY_TABLE (fail-closed
    to the `none` default for unknown names) so the displayed badge can never drift
    from the policy actually enforced. Returns the exploitation ceiling, its 0–3
    rank, a 3-cell ●/○ bar, and human risk flags (lab-only / evasion-on /
    approval-required)."""
    policy = PROFILE_POLICY_TABLE.get(
        normalize_scan_profile_name(profile_name or ""), FAIL_CLOSED_DEFAULT
    )
    rank = ceiling_rank(policy.exploitation_ceiling)
    flags: list[str] = []
    if policy.scope_strictness == "lab-allowlist":
        flags.append("lab-only")
    if policy.evasion_allowed:
        flags.append("evasion-on")
    if policy.deferred_mutation_approval:
        flags.append("approval-required")
    return {
        "ceiling": policy.exploitation_ceiling,
        "rank": rank,
        "bars": "●" * rank + "○" * (len(_CEILING_ORDER) - 1 - rank),
        "flags": flags,
    }


def resolve_policy(config: object | None) -> ScanPolicy:
    """Resolve the active profile to a ScanPolicy. Fail-closed (`none`) on a
    None config, an empty/unset profile, or an unknown profile string. The
    system default `active_profile="crown"` resolves to the crown row."""
    if config is None:
        return FAIL_CLOSED_DEFAULT
    raw = getattr(config, "active_profile", None)
    if not raw or not str(raw).strip():
        return FAIL_CLOSED_DEFAULT
    name = normalize_scan_profile_name(str(raw))
    return PROFILE_POLICY_TABLE.get(name, FAIL_CLOSED_DEFAULT)
