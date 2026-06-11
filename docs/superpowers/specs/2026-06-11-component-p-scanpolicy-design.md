# Component P — Profile-driven ScanPolicy + chokepoints (design)

**Date:** 2026-06-11
**Status:** approved (owner), pending implementation plan
**Plan ref:** `docs/superpowers/plans/2026-06-02-cognitive-engine-v3.md` (lines 90–148, Component P)
**ADR ref:** `wiki/decisions/013_profile_scan_policy.md`

## Motivation

Component P is the **keystone** of the v3 cognitive-engine plan. Every safety-critical
Phase 2 component — H (post-finding exploitation), E (block adaptation), I (ask),
F, R — hangs off a resolved `ScanContext.policy` and the three `permit_*` chokepoints.

A 2026-06-11 recon (9 read-only agents, code-vs-plan) established that **Component P is
0% built**:

- No `src/vxis/agent/policy/scan_policy.py`; no `ScanPolicy` model; no `resolve_policy()`.
- No `permit_pivot` / `permit_strategy` / `persist_secret` chokepoints.
- `ScanContext` (`src/vxis/pipeline/context.py:39`) has no typed `policy` field.
- The existing `src/vxis/p1/` engagement layer (`Engagement`/`Policy`/`Scope` dataclasses)
  is a **separate axis** (per-engagement authorization), not the profile-driven scan policy.

Consequence: there is currently **no enforcement spine** that can DENY out-of-scope pivots,
exfil/persist on prod profiles, or unredacted secret persistence. H cannot be built safely
against this baseline — the plan's own gate ("H cannot merge until the chokepoints land") is
unmet. This spec builds that spine.

The Phase 1.5 scope work already merged (`runtime_gate.py` fail-closed target-host injection,
scope gate wired at `ToolRegistry.dispatch` / Hands egress / Eyes navigation) is **real and
complementary**, but it is the *scope* axis (`ScopeConfig`/`ScopeEnforcer`), decoupled from the
*policy* axis. Component P adds the policy axis and the unified chokepoints that compose the two.

## Approach (chosen: A — pure primitives, no call-site wiring)

Build the policy data + resolution + chokepoint **primitives** with explicit `policy` arguments
and a `ScanContext.policy` field, fully covered by deterministic tests. Do **not** wire the
chokepoints into call sites in this increment — each owning component wires its own site later
(see §8). This keeps P a small, well-bounded, deterministically-testable unit with minimal blast
radius, and matches the plan's "shape now, enforce per-component" philosophy.

Rejected alternatives:
- **B (also wire `permit_pivot` into the shell path now)** — couples P with Phase 1.5 completion;
  the shell path is "UNRESTRICTED by design" today, so wiring it has real blast radius. Split into
  a separate increment.
- **C (extend the `p1/` engagement layer instead of a new module)** — conflates the engagement
  (authorization) axis with the profile (capability) axis, breaking the `min(ceiling, authorization)`
  composition the plan intends as two distinct axes.

## Design

### 1. Module layout — new package `src/vxis/agent/policy/`

- `scan_policy.py` — `ScanPolicy` model, `PROFILE_POLICY_TABLE`, `resolve_policy()`.
- `chokepoints.py` — `permit_pivot` / `permit_strategy` / `persist_secret`, `PolicyDecision`.
- `tests/agent/policy/` — deterministic tests (no LLM).

Two small units: data/resolution vs enforcement decisions.

### 2. `ScanPolicy` model (Pydantic, frozen — CLAUDE.md: no `Any`)

```python
class ScanPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)
    exploitation_ceiling: Literal["none", "read-only", "lateral", "full"]
    scope_strictness:     Literal["lab-allowlist", "strict-authorized"]
    tenant_isolation:     bool
    secret_handling:      Literal["plaintext-lab", "encrypt-redact"]
    evasion_allowed:      bool
    deferred_mutation_approval: bool
```

Immutable: a resolved policy must not mutate mid-scan. `exploitation_ceiling` is ordered
(`none < read-only < lateral < full`) for `min()` composition.

### 3. `PROFILE_POLICY_TABLE` — all 11 profiles + fail-closed default

| profile | ceiling | scope | tenant | secrets | evasion | deferred_appr |
|---|---|---|---|---|---|---|
| crown | **lateral** | strict-authorized | on | encrypt-redact | no | yes |
| aggressive | full | lab-allowlist | off | plaintext-lab | yes | no |
| pre-investment-dd | full | strict-authorized | on | encrypt-redact | ceiling-only† | yes |
| p1-adversary-emulation | **full** | strict-authorized | on | encrypt-redact | ceiling-only† | yes |
| continuous-devsec | read-only | strict-authorized | on | encrypt-redact | no | yes |
| vc-portfolio-monitor | read-only | strict-authorized | on | encrypt-redact | no | yes |
| remediation-verification | read-only | strict-authorized | on | encrypt-redact | no | yes |
| passive | read-only | strict-authorized | on | encrypt-redact | no | yes |
| standard | read-only | strict-authorized | on | encrypt-redact | no | yes |
| stealth | read-only | strict-authorized | on | encrypt-redact | no | yes |
| compliance-mapping | **none** | strict-authorized | on | encrypt-redact | no | yes |
| **unset / alias-miss / unknown** | **none** | strict-authorized | on | encrypt-redact | no | yes |

Owner-confirmed / design decisions:
- **crown = `lateral`** (owner, 2026-06-11): in-scope pivots only, never exfil/persist. The full
  crown-jewel demo (DB dump → exfil) runs only under `aggressive`/lab or `pre-investment-dd`
  (signed one-off scope). Preserves the moat narrative on lab/DD while keeping prod safe.
- **compliance-mapping = `none`**: MITRE→standards mapping only, no active testing. (This row was
  missing from the plan's table — the exact "missing row silently neuters the profile" gotcha.)
- **p1-adversary-emulation = `full`** (owner, 2026-06-11): a real 11th profile (the plan's table
  predates it). Its `_default_profiles()` definition declares `requires_engagement=True` and
  `allowed_techniques=[recon, emulate, c2, lateral, persist]` with `live_capabilities=True`, gated
  by a mandatory attested P1 engagement + scope + hash-chained audit. `full` matches its declared
  techniques; effective capability is still `min(full, engagement authorization)` per hop.
- **† pre-investment-dd evasion**: the profile sets the *ceiling* (allowed), but actual evasion
  (Ghost/Tor) additionally requires the per-engagement "evasion authorized" flag — effective =
  `min()` of the two (plan line 436).
- **deferred_mutation_approval**: `aggressive` = no (auto); all others = yes (require approval,
  fail-closed).

### 4. `resolve_policy(config) -> ScanPolicy`

- Reads `config.active_profile`, normalizes via the existing `normalize_scan_profile_name()`
  (`config/schema.py:400`, handles `_PROFILE_ALIASES`, default `crown`), looks up the table,
  falls through to the fail-closed `none` default on any unknown/missing key.
- **Completeness invariant (test):** every key in `_default_profiles()` AND every alias *target*
  in `_PROFILE_ALIASES` resolves to a table row that is not the accidental fail-closed default
  (parametrized). This is the "no silent neutering" guard the recon flagged.

### 5. Chokepoints + `PolicyDecision`

```python
@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    verdict: Literal["ALLOW", "FORBIDDEN"]   # P returns ALLOW/FORBIDDEN only;
    reason: str                              # APPROVAL_REQUIRED is the engagement axis
```

- **`permit_pivot(target_host, action, policy, scope, *, engagement=None) -> PolicyDecision`**
  - `policy is None` → **FORBIDDEN** (the non-negotiable contract).
  - `data_exfiltration` / `persistence_install` → require ceiling `full`, else FORBIDDEN.
  - `lateral_move` → require ceiling `lateral` or higher, else FORBIDDEN.
  - `target_host` not in scope → FORBIDDEN (not approval-gated).
  - Effective capability = `min(profile ceiling, engagement authorization)`; if `engagement` is
    provided and more restrictive (e.g. `engagement.policy.destructive is False`), downgrade.
  - **`scope` is a thin `Protocol` with `in_scope(host) -> bool`.** This decouples P from Phase
    1.5's not-yet-built `ScopeEnforcer.check_destination(host, port)`; tests pass a fake scope,
    and a real `ScopeEnforcer` adapter lands in Phase 1.5.
- **`permit_strategy(strategy, policy) -> PolicyDecision`**
  - `policy is None` → FORBIDDEN.
  - evasion-class strategy while `evasion_allowed is False` → FORBIDDEN; else ALLOW.
- **`persist_secret(value, policy) -> str | PolicyDecision`**
  - `policy is None` → FORBIDDEN (do not persist).
  - returns a fingerprint (sha256 + last4) unless `secret_handling == "plaintext-lab"` (raw allowed,
    routed to the per-tenant store by the caller).

### 6. `ScanContext` integration

- Add `policy: ScanPolicy | None = None` to `ScanContext` (`pipeline/context.py:39`).
- Resolve at scan start (`resolve_policy(config)`) and attach, behind the `VXIS_V3` /
  `VXIS_V3_POLICY` flag.
- **Default `None`**, never a permissive default — chokepoints treat `None` as FORBIDDEN, so any
  path that builds a context without `resolve_policy` (tests, legacy pipeline, the future resume
  loader) is fail-closed by construction.

### 7. Testing (deterministic, no LLM)

- Table completeness (parametrized over `_default_profiles()` + alias targets).
- `resolve_policy`: crown→lateral, aggressive→full, unknown/unset→none, alias resolves.
- **DENY-on-None** for all three chokepoints.
- `permit_pivot`: crown refuses exfil/persist; crown allows in-scope `lateral_move`; out-of-scope
  host FORBIDDEN even at `full`; `aggressive` `full` allows exfil only under `lab-allowlist`;
  `min(ceiling, engagement)` downgrades when engagement is more restrictive.
- `permit_strategy`: evasion FORBIDDEN unless `evasion_allowed`.
- `persist_secret`: fingerprints unless `plaintext-lab`; None → FORBIDDEN.
- `ScanContext.policy` resolves at scan start under flag; absent → None.

### 8. Explicitly out of scope for this increment

Each is wired by its owning component later:

- `permit_pivot` → shell/exploit dispatch — Phase 1.5 / H.
- `ScopeEnforcer.check_destination(host, port)` + `data_exfiltration` / `persistence_install` /
  `lateral_move` as real scope `ActionPolicy` classes — Phase 1.5.
- `permit_strategy` → block-adaptation dispatch — Component E.
- `persist_secret` → findings[] redaction chokepoint — Component V.
- `tenant_id` on `Dossier` + tenant-scoped store path — Component A.

## Delivery

Per CLAUDE.md: TDD (failing tests first), one phase = one commit, `/code-review` per commit,
main-only push (feature branch `feat/component-p-scanpolicy`, deleted after merge). Commit prefix
`feat(policy):`.
