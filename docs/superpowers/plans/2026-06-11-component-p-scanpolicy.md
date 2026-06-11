# Component P — ScanPolicy + Chokepoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the profile-driven `ScanPolicy` model, its profile→policy table + `resolve_policy()`, and the three fail-closed chokepoints (`permit_pivot` / `permit_strategy` / `persist_secret`) plus a `ScanContext.policy` field — the safety keystone every Phase-2 component depends on.

**Architecture:** New self-contained package `src/vxis/agent/policy/`. Pure primitives with explicit `policy` arguments; chokepoints DENY when `policy is None`. The `scope` argument to `permit_pivot` is a thin `Protocol` so P does not depend on Phase 1.5's not-yet-built `ScopeEnforcer.check_destination`. NO call-site wiring in this increment beyond resolving+attaching `ScanContext.policy` at scan start behind a flag.

**Tech Stack:** Python 3.12, Pydantic v2 (`pydantic>=2.9`), pytest. Spec: `docs/superpowers/specs/2026-06-11-component-p-scanpolicy-design.md`.

---

## File Structure

- Create `src/vxis/agent/policy/__init__.py` — package marker + public exports.
- Create `src/vxis/agent/policy/scan_policy.py` — `ScanPolicy` model, `PROFILE_POLICY_TABLE`, `FAIL_CLOSED_DEFAULT`, `resolve_policy()`, `ceiling_rank()`.
- Create `src/vxis/agent/policy/chokepoints.py` — `PolicyDecision`, `ScopeLike`/`EngagementLike` protocols, `permit_strategy`, `persist_secret`, `permit_pivot`.
- Modify `src/vxis/pipeline/context.py` — add `policy: ScanPolicy | None = None` field (TYPE_CHECKING import).
- Modify `src/vxis/pipeline/scan_pipeline_v2.py` (after the `ctx = ScanContext(...)` build at line ~663) — resolve + attach behind the `VXIS_V3_POLICY`/`VXIS_V3` flag.
- Create `tests/agent/policy/__init__.py`, `tests/agent/policy/test_scan_policy.py`, `tests/agent/policy/test_chokepoints.py`, `tests/agent/policy/test_scancontext_policy.py`.

Reused existing code: `normalize_scan_profile_name` + `_default_profiles` + `_PROFILE_ALIASES` (`src/vxis/config/schema.py`), `v3_flag` (`src/vxis/agent/scan_loop_v3.py:19`), `ScanPipeline.self.config` (`src/vxis/pipeline/scan_pipeline_v2.py:611`).

Run tests with the project venv: `.venv/bin/python -m pytest`.

---

### Task 1: Package scaffold + `ScanPolicy` model

**Files:**
- Create: `src/vxis/agent/policy/__init__.py`
- Create: `src/vxis/agent/policy/scan_policy.py`
- Test: `tests/agent/policy/__init__.py`, `tests/agent/policy/test_scan_policy.py`

- [ ] **Step 1: Write the failing test**

Create `tests/agent/policy/__init__.py` (empty) and `tests/agent/policy/test_scan_policy.py`:

```python
import pytest
from pydantic import ValidationError

from vxis.agent.policy.scan_policy import ScanPolicy, ceiling_rank


def _policy(**overrides):
    base = dict(
        exploitation_ceiling="lateral",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=False,
        deferred_mutation_approval=True,
    )
    base.update(overrides)
    return ScanPolicy(**base)


def test_scan_policy_is_frozen():
    p = _policy()
    with pytest.raises(ValidationError):
        p.exploitation_ceiling = "full"


def test_scan_policy_rejects_unknown_ceiling():
    with pytest.raises(ValidationError):
        _policy(exploitation_ceiling="god-mode")


def test_ceiling_rank_is_ordered():
    assert ceiling_rank("none") < ceiling_rank("read-only") < ceiling_rank("lateral") < ceiling_rank("full")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scan_policy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'vxis.agent.policy'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/vxis/agent/policy/__init__.py`:

```python
"""Component P — profile-driven ScanPolicy + fail-closed chokepoints."""

from vxis.agent.policy.scan_policy import (
    FAIL_CLOSED_DEFAULT,
    PROFILE_POLICY_TABLE,
    ScanPolicy,
    ceiling_rank,
    resolve_policy,
)

__all__ = [
    "ScanPolicy",
    "PROFILE_POLICY_TABLE",
    "FAIL_CLOSED_DEFAULT",
    "resolve_policy",
    "ceiling_rank",
]
```

Create `src/vxis/agent/policy/scan_policy.py` (model + rank only for now; table/resolve added in Task 2):

```python
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
```

Note: Pydantic v2 `frozen=True` raises `ValidationError` on attribute assignment.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scan_policy.py -q`
Expected: PASS (3 passed). The `__init__.py` import of `resolve_policy`/`PROFILE_POLICY_TABLE` will fail until Task 2 — so for Task 1 temporarily export only `ScanPolicy`/`ceiling_rank` in `__init__.py`, OR implement Task 2 in the same session before importing the package elsewhere. Simplest: keep `__init__.py` minimal in Task 1:

```python
"""Component P — profile-driven ScanPolicy + fail-closed chokepoints."""

from vxis.agent.policy.scan_policy import ScanPolicy, ceiling_rank

__all__ = ["ScanPolicy", "ceiling_rank"]
```

(Task 2 extends `__all__`.) Re-run; expected PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/policy/__init__.py src/vxis/agent/policy/scan_policy.py tests/agent/policy/
git commit -m "feat(policy): ScanPolicy frozen model + ceiling_rank"
```

---

### Task 2: `PROFILE_POLICY_TABLE` + `resolve_policy` + completeness invariant

**Files:**
- Modify: `src/vxis/agent/policy/scan_policy.py`
- Modify: `src/vxis/agent/policy/__init__.py`
- Test: `tests/agent/policy/test_scan_policy.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/agent/policy/test_scan_policy.py`:

```python
from vxis.agent.policy.scan_policy import (
    FAIL_CLOSED_DEFAULT,
    PROFILE_POLICY_TABLE,
    resolve_policy,
)
from vxis.config.schema import _PROFILE_ALIASES, _default_profiles, normalize_scan_profile_name


class _Cfg:
    def __init__(self, active_profile):
        self.active_profile = active_profile


def test_resolve_crown_is_lateral():
    assert resolve_policy(_Cfg("crown")).exploitation_ceiling == "lateral"


def test_resolve_aggressive_is_full_lab():
    p = resolve_policy(_Cfg("aggressive"))
    assert p.exploitation_ceiling == "full"
    assert p.scope_strictness == "lab-allowlist"
    assert p.secret_handling == "plaintext-lab"


def test_resolve_p1_alias_is_full():
    # "p1" is an alias for "p1-adversary-emulation"
    assert resolve_policy(_Cfg("p1")).exploitation_ceiling == "full"


def test_resolve_compliance_mapping_is_none():
    assert resolve_policy(_Cfg("compliance-mapping")).exploitation_ceiling == "none"


def test_resolve_unknown_profile_is_fail_closed():
    assert resolve_policy(_Cfg("totally-made-up")) == FAIL_CLOSED_DEFAULT
    assert resolve_policy(_Cfg("totally-made-up")).exploitation_ceiling == "none"


def test_resolve_none_config_is_fail_closed():
    assert resolve_policy(None) == FAIL_CLOSED_DEFAULT


def test_resolve_empty_profile_is_fail_closed():
    assert resolve_policy(_Cfg("")).exploitation_ceiling == "none"
    assert resolve_policy(_Cfg(None)).exploitation_ceiling == "none"


def test_every_builtin_profile_has_an_explicit_policy_row():
    """No silent neutering: every built-in profile resolves to an EXPLICIT
    table row, never the accidental fail-closed fallthrough."""
    for name in _default_profiles():
        assert name in PROFILE_POLICY_TABLE, f"profile {name!r} missing from PROFILE_POLICY_TABLE"


def test_every_alias_target_has_an_explicit_policy_row():
    for alias, target in _PROFILE_ALIASES.items():
        # alias may normalize to crown for the empty string; assert the resolved
        # target has a row.
        resolved = normalize_scan_profile_name(alias)
        assert resolved in PROFILE_POLICY_TABLE, f"alias {alias!r}->{resolved!r} has no policy row"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scan_policy.py -q`
Expected: FAIL — `ImportError: cannot import name 'PROFILE_POLICY_TABLE'`.

- [ ] **Step 3: Write minimal implementation**

Append to `src/vxis/agent/policy/scan_policy.py`:

```python
from vxis.config.schema import normalize_scan_profile_name

# Fail-closed default: any None config / empty / unknown profile lands here.
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
        evasion_allowed=True,  # ceiling only; actual evasion gated by engagement flag
        deferred_mutation_approval=True,
    ),
    "p1-adversary-emulation": ScanPolicy(
        exploitation_ceiling="full",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=True,  # ceiling only; gated by attested P1 engagement
        deferred_mutation_approval=True,
    ),
    "continuous-devsec": _PROD_READONLY,
    "vc-portfolio-monitor": _PROD_READONLY,
    "remediation-verification": _PROD_READONLY,
    "passive": _PROD_READONLY,
    "standard": _PROD_READONLY,
    "stealth": _PROD_READONLY,
    "compliance-mapping": ScanPolicy(
        exploitation_ceiling="none",  # MITRE->standards mapping only, no active testing
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=False,
        deferred_mutation_approval=True,
    ),
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
```

Update `src/vxis/agent/policy/__init__.py` to export the new names:

```python
"""Component P — profile-driven ScanPolicy + fail-closed chokepoints."""

from vxis.agent.policy.scan_policy import (
    FAIL_CLOSED_DEFAULT,
    PROFILE_POLICY_TABLE,
    ScanPolicy,
    ceiling_rank,
    resolve_policy,
)

__all__ = [
    "ScanPolicy",
    "PROFILE_POLICY_TABLE",
    "FAIL_CLOSED_DEFAULT",
    "resolve_policy",
    "ceiling_rank",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scan_policy.py -q`
Expected: PASS (all tests). If `test_every_alias_target_has_an_explicit_policy_row` fails, a profile/alias is missing a row — add it.

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/policy/scan_policy.py src/vxis/agent/policy/__init__.py tests/agent/policy/test_scan_policy.py
git commit -m "feat(policy): PROFILE_POLICY_TABLE (11 profiles) + fail-closed resolve_policy"
```

---

### Task 3: `PolicyDecision` + `permit_strategy` (+ protocols)

**Files:**
- Create: `src/vxis/agent/policy/chokepoints.py`
- Modify: `src/vxis/agent/policy/__init__.py`
- Test: `tests/agent/policy/test_chokepoints.py`

- [ ] **Step 1: Write the failing test**

Create `tests/agent/policy/test_chokepoints.py`:

```python
from vxis.agent.policy.chokepoints import PolicyDecision, permit_strategy
from vxis.agent.policy.scan_policy import ScanPolicy


def _policy(**overrides):
    base = dict(
        exploitation_ceiling="lateral",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=False,
        deferred_mutation_approval=True,
    )
    base.update(overrides)
    return ScanPolicy(**base)


def test_permit_strategy_denies_on_none_policy():
    d = permit_strategy("ghost", None)
    assert d.allowed is False
    assert d.verdict == "FORBIDDEN"


def test_permit_strategy_blocks_evasion_when_not_allowed():
    d = permit_strategy("ghost", _policy(evasion_allowed=False))
    assert d.allowed is False


def test_permit_strategy_allows_evasion_when_allowed():
    d = permit_strategy("ghost", _policy(evasion_allowed=True))
    assert d.allowed is True
    assert d.verdict == "ALLOW"


def test_permit_strategy_allows_non_evasion_strategy():
    d = permit_strategy("skill_mutation", _policy(evasion_allowed=False))
    assert d.allowed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_chokepoints.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'vxis.agent.policy.chokepoints'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/vxis/agent/policy/chokepoints.py`:

```python
"""Fail-closed enforcement chokepoints (Component P).

Each chokepoint returns a PolicyDecision and treats `policy is None` as
FORBIDDEN — a profile sets strictness but can never substitute for the
chokepoint. Call-site wiring (shell path, block adaptation, findings[]) is
owned by Phase 1.5 / E / V respectively; this module is the primitive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from vxis.agent.policy.scan_policy import ScanPolicy

# Canonical evasion strategy identifiers. Component E owns the full taxonomy;
# P only needs to know which strategies are evasion-class.
_EVASION_STRATEGIES = frozenset({"ghost", "tor", "proxy_rotation", "source_ip_rotation"})


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    verdict: Literal["ALLOW", "FORBIDDEN"]
    reason: str
    stored_value: str | None = None  # set by persist_secret only


def _forbidden(reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, verdict="FORBIDDEN", reason=reason)


def _allow(reason: str = "", stored_value: str | None = None) -> PolicyDecision:
    return PolicyDecision(allowed=True, verdict="ALLOW", reason=reason, stored_value=stored_value)


def permit_strategy(strategy: str, policy: ScanPolicy | None) -> PolicyDecision:
    if policy is None:
        return _forbidden("policy is None (fail-closed)")
    if strategy.lower() in _EVASION_STRATEGIES and not policy.evasion_allowed:
        return _forbidden(f"evasion strategy '{strategy}' not permitted by policy")
    return _allow()
```

Add `permit_strategy` and `PolicyDecision` to `__init__.py` `__all__` and imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_chokepoints.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/policy/chokepoints.py src/vxis/agent/policy/__init__.py tests/agent/policy/test_chokepoints.py
git commit -m "feat(policy): PolicyDecision + permit_strategy chokepoint (DENY-on-None)"
```

---

### Task 4: `persist_secret`

**Files:**
- Modify: `src/vxis/agent/policy/chokepoints.py`
- Test: `tests/agent/policy/test_chokepoints.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/agent/policy/test_chokepoints.py`:

```python
import hashlib

from vxis.agent.policy.chokepoints import persist_secret


def test_persist_secret_denies_on_none_policy():
    d = persist_secret("hunter2", None)
    assert d.allowed is False
    assert d.verdict == "FORBIDDEN"
    assert d.stored_value is None


def test_persist_secret_fingerprints_when_encrypt_redact():
    d = persist_secret("supersecrettoken", _policy(secret_handling="encrypt-redact"))
    assert d.allowed is True
    assert "supersecrettoken" not in d.stored_value
    expected = hashlib.sha256(b"supersecrettoken").hexdigest()
    assert expected in d.stored_value
    assert d.stored_value.endswith("oken")  # last4 retained


def test_persist_secret_returns_raw_when_plaintext_lab():
    d = persist_secret("supersecrettoken", _policy(secret_handling="plaintext-lab"))
    assert d.allowed is True
    assert d.stored_value == "supersecrettoken"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_chokepoints.py -q -k persist_secret`
Expected: FAIL — `ImportError: cannot import name 'persist_secret'`.

- [ ] **Step 3: Write minimal implementation**

Append to `src/vxis/agent/policy/chokepoints.py` (add `import hashlib` at top):

```python
def _fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    last4 = value[-4:] if len(value) >= 4 else value
    return f"sha256:{digest}:{last4}"


def persist_secret(value: str, policy: ScanPolicy | None) -> PolicyDecision:
    if policy is None:
        return _forbidden("policy is None (fail-closed)")
    if policy.secret_handling == "plaintext-lab":
        return _allow("plaintext-lab", stored_value=value)
    return _allow("fingerprinted", stored_value=_fingerprint(value))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_chokepoints.py -q`
Expected: PASS (7 passed total in the file).

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/policy/chokepoints.py tests/agent/policy/test_chokepoints.py
git commit -m "feat(policy): persist_secret chokepoint (sha256 fingerprint unless plaintext-lab)"
```

---

### Task 5: `permit_pivot` (the destructive-action gate)

**Files:**
- Modify: `src/vxis/agent/policy/chokepoints.py`
- Modify: `src/vxis/agent/policy/__init__.py`
- Test: `tests/agent/policy/test_chokepoints.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/agent/policy/test_chokepoints.py`:

```python
from vxis.agent.policy.chokepoints import permit_pivot


class _Scope:
    def __init__(self, allowed_hosts):
        self._hosts = set(allowed_hosts)

    def in_scope(self, host: str) -> bool:
        return host in self._hosts


class _Engagement:
    def __init__(self, ceiling):
        self._ceiling = ceiling

    def authorized_ceiling(self) -> str:
        return self._ceiling


_IN = _Scope({"10.0.0.5"})


def test_permit_pivot_denies_on_none_policy():
    d = permit_pivot("10.0.0.5", "lateral_move", None, _IN)
    assert d.verdict == "FORBIDDEN"


def test_permit_pivot_read_only_cannot_pivot():
    d = permit_pivot("10.0.0.5", "lateral_move", _policy(exploitation_ceiling="read-only"), _IN)
    assert d.allowed is False


def test_permit_pivot_lateral_allows_in_scope_lateral_move():
    d = permit_pivot("10.0.0.5", "lateral_move", _policy(exploitation_ceiling="lateral"), _IN)
    assert d.allowed is True


def test_permit_pivot_lateral_refuses_exfil():
    d = permit_pivot("10.0.0.5", "data_exfiltration", _policy(exploitation_ceiling="lateral"), _IN)
    assert d.allowed is False


def test_permit_pivot_full_allows_exfil_in_scope():
    d = permit_pivot("10.0.0.5", "data_exfiltration", _policy(exploitation_ceiling="full"), _IN)
    assert d.allowed is True


def test_permit_pivot_out_of_scope_forbidden_even_at_full():
    d = permit_pivot("8.8.8.8", "lateral_move", _policy(exploitation_ceiling="full"), _IN)
    assert d.allowed is False
    assert "scope" in d.reason.lower()


def test_permit_pivot_engagement_downgrades_ceiling():
    # policy permits full, but engagement only authorizes lateral -> exfil refused
    d = permit_pivot(
        "10.0.0.5",
        "data_exfiltration",
        _policy(exploitation_ceiling="full"),
        _IN,
        engagement=_Engagement("lateral"),
    )
    assert d.allowed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_chokepoints.py -q -k permit_pivot`
Expected: FAIL — `ImportError: cannot import name 'permit_pivot'`.

- [ ] **Step 3: Write minimal implementation**

Append to `src/vxis/agent/policy/chokepoints.py` (add `from vxis.agent.policy.scan_policy import ceiling_rank` to the existing scan_policy import line):

```python
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
```

Add `permit_pivot`, `persist_secret`, `ScopeLike`, `EngagementLike` to `__init__.py` exports.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_chokepoints.py -q`
Expected: PASS (all chokepoint tests).

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/policy/chokepoints.py src/vxis/agent/policy/__init__.py tests/agent/policy/test_chokepoints.py
git commit -m "feat(policy): permit_pivot chokepoint (ceiling + scope + engagement min)"
```

---

### Task 6: `ScanContext.policy` field

**Files:**
- Modify: `src/vxis/pipeline/context.py`
- Test: `tests/agent/policy/test_scancontext_policy.py`

- [ ] **Step 1: Write the failing test**

Create `tests/agent/policy/test_scancontext_policy.py`:

```python
from vxis.interaction.surface import TargetKind
from vxis.pipeline.context import ScanContext


def test_scancontext_policy_defaults_to_none():
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    assert ctx.policy is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scancontext_policy.py -q`
Expected: FAIL — `AttributeError: 'ScanContext' object has no attribute 'policy'`.

- [ ] **Step 3: Write minimal implementation**

In `src/vxis/pipeline/context.py`, add the TYPE_CHECKING import near the top (after `from typing import Any`):

```python
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vxis.agent.policy.scan_policy import ScanPolicy
```

Add the field to the `ScanContext` dataclass (e.g. right after `started_at`, around line 50). Because `context.py` already has `from __future__ import annotations`, the annotation is lazy — no runtime import needed:

```python
    # ── Component P: resolved scan policy (None = fail-closed at chokepoints) ──
    policy: "ScanPolicy | None" = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scancontext_policy.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vxis/pipeline/context.py tests/agent/policy/test_scancontext_policy.py
git commit -m "feat(policy): add ScanContext.policy field (default None, fail-closed)"
```

---

### Task 7: Resolve + attach policy at scan start (behind flag)

**Files:**
- Modify: `src/vxis/pipeline/scan_pipeline_v2.py` (right after the `ctx = ScanContext(...)` build, ~line 663)
- Test: `tests/agent/policy/test_scancontext_policy.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/agent/policy/test_scancontext_policy.py`:

```python
from vxis.agent.policy.scan_policy import resolve_policy
from vxis.config.schema import VXISConfig


def test_resolve_policy_attaches_to_context_for_crown(monkeypatch):
    # Simulate the wiring step directly (unit-level; full pipeline run is a live test).
    cfg = VXISConfig()
    cfg.active_profile = "crown"
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    ctx.policy = resolve_policy(cfg)
    assert ctx.policy is not None
    assert ctx.policy.exploitation_ceiling == "lateral"
```

(The pipeline-level attach is exercised by the deterministic suite plus, later, a live scan; this unit test pins the resolve+attach contract the wiring uses.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/agent/policy/test_scancontext_policy.py -q`
Expected: PASS for the new test's logic (resolve_policy exists) — if it fails it indicates a resolve/import regression. This step's REAL change is the pipeline wiring below; verify it by reading the diff and the full-suite run in Step 4.

- [ ] **Step 3: Write the pipeline wiring**

In `src/vxis/pipeline/scan_pipeline_v2.py`, immediately after the `ctx = ScanContext(...)` block ends (after line ~663, before `ctx.runtime_profile = {...}`), insert:

```python
            # Component P: resolve + attach the scan policy (fail-closed default
            # when the flag is off or the profile is unknown). No chokepoint is
            # wired in this increment; this only makes ctx.policy available.
            from vxis.agent.policy.scan_policy import resolve_policy
            from vxis.agent.scan_loop_v3 import v3_flag

            if v3_flag("VXIS_V3_POLICY") or v3_flag("VXIS_V3"):
                ctx.policy = resolve_policy(self.config)
```

- [ ] **Step 4: Run tests to verify nothing breaks**

Run: `.venv/bin/python -m pytest tests/agent/policy/ -q`
Expected: PASS.
Run the full deterministic suite to confirm no regression: `.venv/bin/python -m pytest -m "not live" -q`
Expected: PASS (prior baseline 2330 passed + the new policy tests).

- [ ] **Step 5: Lint + commit**

```bash
.venv/bin/ruff check src/vxis/agent/policy/ src/vxis/pipeline/context.py src/vxis/pipeline/scan_pipeline_v2.py
.venv/bin/ruff format --check src/vxis/agent/policy/ src/vxis/pipeline/context.py src/vxis/pipeline/scan_pipeline_v2.py
git add src/vxis/pipeline/scan_pipeline_v2.py tests/agent/policy/test_scancontext_policy.py
git commit -m "feat(policy): resolve + attach ScanContext.policy at scan start behind VXIS_V3_POLICY"
```

---

## Self-Review

**Spec coverage:**
- ScanPolicy model (§2) → Task 1. ✓
- PROFILE_POLICY_TABLE all 11 + fail-closed default (§3) → Task 2 (incl. p1-adversary-emulation=full, compliance-mapping=none). ✓
- resolve_policy + completeness invariant (§4) → Task 2. ✓
- PolicyDecision + 3 chokepoints, DENY-on-None, scope Protocol (§5) → Tasks 3–5. ✓
- ScanContext.policy field, default None, resolve at scan start behind flag (§6) → Tasks 6–7. ✓
- Out-of-scope items (§8: shell wiring, check_destination, E/V wiring, tenant_id) → correctly NOT in any task. ✓

**Refinements vs spec (intentional, captured here):**
- `persist_secret` returns a `PolicyDecision` with a `stored_value` field rather than the spec's awkward `str | PolicyDecision`. Uniform return type across all three chokepoints.
- `permit_pivot`'s `engagement` is an `EngagementLike` Protocol exposing `authorized_ceiling()` (the real p1 `Engagement`→ceiling adapter maps attested/destructive→ceiling and is wired later). The spec's `engagement.policy.destructive` was illustrative.
- `pre-investment-dd` / `p1-adversary-emulation` set `evasion_allowed=True` as the ceiling; actual evasion is additionally gated by the per-engagement evasion flag at the `permit_strategy` call site (Component E), not in P.

**Placeholder scan:** none — every step has complete code + exact commands.

**Type consistency:** `ScanPolicy`, `PolicyDecision`, `ceiling_rank`, `resolve_policy`, `permit_pivot/permit_strategy/persist_secret`, `ScopeLike`/`EngagementLike` names are consistent across tasks and `__init__.py` exports.

**Note on Task 1 `__init__.py`:** Task 1 ships a minimal `__init__.py` (exports `ScanPolicy`, `ceiling_rank` only); Task 2 extends it to the full export list. This avoids an import error between the two commits.
