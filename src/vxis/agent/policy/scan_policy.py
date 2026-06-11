"""ScanPolicy model + profile→policy resolution (Component P).

A ScanPolicy is the *capability* axis (what the profile permits), composed
later with the *authorization* axis (per-engagement) via min(). Immutable:
a resolved policy must not mutate mid-scan.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

Ceiling = Literal["none", "read-only", "lateral", "full"]

_CEILING_ORDER: dict[str, int] = {"none": 0, "read-only": 1, "lateral": 2, "full": 3}


def ceiling_rank(ceiling: str) -> int:
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
