"""Component P — profile-driven ScanPolicy + fail-closed chokepoints."""

from vxis.agent.policy.chokepoints import (
    EngagementLike,
    PolicyDecision,
    ScopeLike,
    permit_pivot,
    permit_strategy,
    persist_secret,
)
from vxis.agent.policy.scan_policy import (
    FAIL_CLOSED_DEFAULT,
    PROFILE_POLICY_TABLE,
    Ceiling,
    ScanPolicy,
    ceiling_rank,
    resolve_policy,
)

__all__ = [
    "Ceiling",
    "ScanPolicy",
    "PROFILE_POLICY_TABLE",
    "FAIL_CLOSED_DEFAULT",
    "resolve_policy",
    "ceiling_rank",
    "PolicyDecision",
    "permit_strategy",
    "persist_secret",
    "permit_pivot",
    "ScopeLike",
    "EngagementLike",
]
