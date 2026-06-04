# 2026-06-02 — Cognitive Engine v3 (Integration, Consolidation & Safety)

> **This file is the in-place rewrite of the original v3 plan** (the A–K / "beyond v3" / "Component J"
> taxonomy referenced below comes from that original draft, now superseded by this file). It follows
> [`2026-06-01-vxis-v2-strategy-and-engine.md`](2026-06-01-vxis-v2-strategy-and-engine.md).
>
> **Rewrite history**
> - **v3.0** — first rewrite after a code-level competitive review (Strix, PentAGI, PentestAgent,
>   pentest-ai-agents, Metatron): reframed build→integrate, re-centered on the verifier moat, pulled H in.
> - **v3.1** — after an 8-reviewer plan-review against the actual tree. Three classes of change:
>   (1) **factual corrections** — several "to build" items already exist, and three systems the plan must
>   consolidate were mis-counted; (2) **a profile-driven safety model** (`ScanPolicy`) unifying
>   exploitation-depth + tenant-isolation + evasion into one profile-keyed axis; (3) **a realistic 3-tier
>   benchmark/CI strategy** (the league is a spec today, not a runner).
> - **v3.2 (this version)** — after a focused second review of the new v3.1 material. Fixes: the policy
>   table omitted the default `crown` profile (would neuter the engine) and keyed `full` off a non-existent
>   `benchmark` profile; `resolve_policy`/`ScanContext` wiring was wrong; **`ScopeEnforcer` is un-wired,
>   broken, URL-shaped, and fails *open* on empty scope** (Phase 1.5 now fixes+wires+extends it); tenant
>   identity needed a trust root + store-level read guard (validator alone is decorative); **report-path
>   secret redaction** must co-locate with verify at the `findings[]` chokepoint; chokepoints must DENY on
>   `policy=None`; the **benchmark split is a build** (no cassette substrate exists, live-on-PR still wired,
>   variance harness is a Phase 0.5 project); dual-write window must not leak secrets to the un-tenanted
>   legacy store; status vocabulary canonicalized; Z given an exit criterion; `#current-state` anchor fixed.
>
> **Read the [Current State](#current-state) before anything — most "Create…" work is actually wire/harden/delete.**

## Goal

Make `crown` behave like a senior pentester who has worked on the same target before — fast on the next
scan because it remembers, ruthless at finishing because coverage is measured, deep because it chains a
confirmed finding toward a crown jewel **when the engagement authorizes it**, and trusted because every
reported finding survived adversarial verification with a PoC. Cognitive depth + operational autonomy
remain the two locked axes; both now serve the **precision (zero-FP) + chain-depth** moat, and both are
bounded by an explicit **per-profile safety policy** so the same engine is safe on customer prod and
unrestricted in the lab.

## Strategic Recalibration

The competitive read: every competitor's intelligence lives in a prompt + a single frontier model; code
investment goes to orchestration, not cognition. The universal failure mode is **false positives /
unverified findings**. VXIS's declared moat — *adversarial verifier → zero-FP → chain to crown jewel →
MITRE → bilingual NCC report* — is the open wedge.

| Capability | Strix | PentAGI | PentestAgent | Open ground? |
|---|---|---|---|---|
| Per-target persistent dossier | resume only | technique-KB, not per-target | session notes | **yes** |
| Explicit hypothesis/belief tracking | no-op `think` | none | task-step plan | **yes** |
| Measured coverage-gated completion | vibes + max_turns | subtask status | plan completion | **yes** |
| WAF/block detection + adaptation | prompt advice | none | none | **yes** |
| Cost/model routing | single model | per-agent (strong) | none | no (PentAGI wins) |
| Multi-agent swarm | production-grade | hierarchical | crew/MCP | no (don't fight) |
| Finding-quality verification (zero-FP) | convention | loop-detection | reactive | **yes — our moat** |

So: **Verifier (spine) ← DAG chains (depth) ← Coverage (finish) ← PTI (memory) ← Policy/Block/Ask/Cost (support).**
Cost routing is parity, not moat — it stays as a margin optimization, not a headline.

## Current State

> Audit of the working tree, 2026-06-02.

These exist as **untracked code behind `VXIS_V3` (default off)** and pass **57 tests**
(`pytest tests/{pti,agent/hypothesis,agent/coverage,agent/routing,agent/ask,agent/block,agent/critique}`):

| ID | Module | LOC | Status / correction vs original plan |
|---|---|---|---|
| A | `src/vxis/pti/` (models, store, query, hashing, trajectory) | ~855 | library done. **`Dossier` has NO `to_summary()`** → today it gets `str()[:N]`-sliced (content-destroying). **No tenant dimension, no retention/quota.** |
| B | `src/vxis/agent/hypothesis/dag.py` + `bayes.py` | ~464 | library done. **Real API is `add/update_belief/prune_dead/top_untested/query/to_summary/status_counts/next_node_id`** — the original plan's `seed/prioritize_hypothesis/update_hypothesis/generate_hypotheses` do NOT exist. Edges are untyped. |
| C | `src/vxis/agent/routing/cost_router.py` | ~220 | library done, but a **third** model table; `brain._model_role_for_decision_class()` (`brain.py:818`, flag `VXIS_V3_ROLE_ROUTING`) already maps decision-class→`ModelRole`. The three tables disagree. |
| D | `src/vxis/agent/coverage/matrix.py` | ~369 | library done (`to_summary` correct). |
| E | `src/vxis/agent/block/classifier.py` | ~486 | library done; Ghost layer at **`src/vxis/ghost/`** (original plan's `agent/ghost/*` path is wrong). |
| F | `src/vxis/agent/critique/loop.py` | ~426 | library done and **deterministic (no LLM today)**. Runs **every iter** + `force=True` on every finish; **the `cap=5` is NOT implemented**. |
| I | `src/vxis/agent/ask/queue.py` + `tools/ask_human.py` | ~222 | library done. `assumed_safe_default=True` is asserted on skip/timeout/cap paths **without verifying the default is actually the safe/non-action branch**. |
| V | `src/vxis/agent/verify/` | — | **~70% already exists, NOT new**: `verifier_tools.py` ("default to refute", CONFIRMED/UNCONFIRMED/REFUTED, thin-claim/binary-evidence gates) + a live gate in `scan_loop_run.py:489-618` that blocks REFUTED. **Two real gaps:** gate fires only for `severity in (high,critical)` (`scan_loop_run.py:496`) so medium/low bypass; gate sits at the Brain `report_finding` boundary, not the `findings[]` chokepoint (skill auto-reporting bypasses it). |
| H, R | `agent/exploit/`, `agent/resume/` | — | genuinely do **not** exist yet (new builds). |
| — | `scan_loop_v3.py`, dashboard `v3_dashboard_summary()` | ~248 | wiring partially done; the **v3 finish gate STACKS on top of the 5 legacy gates** (`scan_loop_run.py:1538` runs after the legacy branches at ~1303-1315), it does not replace them. |

**The real work is: consolidate overlaps, add a safety policy layer, harden the verifier, wire the loop,
build H/R + the scope chokepoint H needs, and make the benchmark gate real. Not "create the modules."**

### Pre-existing overlaps that MUST be consolidated (corrected counts)

| New v3 surface | Pre-existing overlap(s) — VERIFIED | Decision |
|---|---|---|
| PTI dossier | **TWO separate systems, not one:** (1) `AgentMemory`/`ScanMemory` (`agent/memory.py`), an in-process object consumed by `core/orchestrator.py:735` and `brain.py:1770` (`recall_similar`); (2) the JSON KB behind the `query_scan_memory` BrainTool (`tools/memory_tools.py:514`, own `_load_kb`). They do not share storage. | PTI absorbs **both**. Re-point `orchestrator.py:735` + `brain.py:1770` at the dossier; re-back `query_scan_memory` on PTI. Phase-0 grep must check `AgentMemory`, `remember_scan`, AND `recall_similar` call sites. |
| `agent/hypothesis/dag.py` `Hypothesis` | `graph/hypothesis.py` `Hypothesis`/`HypothesisQueue`/`HypothesisGenerator` (`from_finding()` only) | Rename new class `HypothesisNode`; keep `HypothesisGenerator.from_finding()` as a DAG seed source if still used by `runner.py`/`director.py`; retire `HypothesisQueue`. |
| model routing | **THREE tables:** `cost_router.ROUTE_TABLE`, `hybrid_config` role endpoints, `brain._model_role_for_decision_class()`. They disagree (e.g. verify→opus vs verify→VERIFIER=sonnet). | Keep `brain._model_role_for_decision_class` as the one map; delete `cost_router.ROUTE_TABLE` (keep its `CostReport` telemetry); reconcile the verify model explicitly. |
| prioritization | **FOUR-to-FIVE coupled stores, not three:** `ensure_vector_candidate()` (`scan_loop_state.py:471`) fans out to `vector_candidates` + `scan_todos` + `branches` (`BranchState`, 25+ fields) + a control-state mirror. | DAG is sole prioritizer. Phase 0 needs a **field-level mapping table** for all of them (per-field: migrate to `HypothesisNode` / move to a side-table keyed by `node_id` / delete), including `scan_todos`. |

## Profile-driven Safety — Component P (NEW, the unifier for exploitation-depth + isolation + evasion)

**Decision (owner, 2026-06-02):** exploitation depth, tenant isolation, secret handling, and evasion are
**one axis keyed off the starting profile**, not global flags. The same engine runs unrestricted in the
lab and capped on customer prod, decided by which profile launched the scan.

```python
# src/vxis/agent/policy/scan_policy.py  (NEW)
class ScanPolicy(BaseModel):
    exploitation_ceiling: Literal["none", "read-only", "lateral", "full"]
    scope_strictness:     Literal["lab-allowlist", "strict-authorized"]
    tenant_isolation:     bool
    secret_handling:      Literal["plaintext-lab", "encrypt-redact"]
    evasion_allowed:      bool          # Ghost/Tor rotation
    deferred_mutation_approval: bool
```

**Profile → policy.** `resolve_policy()` reads `config.active_profile` (the **normalized**, post-alias
name — `config/schema.py:355`; default is `crown`), NOT a passed-in `profile` arg. Rows must exist for
**every** profile in `_default_profiles()` (`crown`/`passive`/`stealth`/`aggressive`/`standard`) plus the
v2 business profiles — a missing row falls through to the fail-closed default and silently neuters that
profile (this is exactly the bug the first draft of this table caused for `crown`).

| Profile | exploitation | scope | tenant_isolation | secrets | evasion |
|---|---|---|---|---|---|
| `crown` (default flagship) | `lateral` (in-scope pivots; **no** exfil/persist) | `strict-authorized` | on | `encrypt-redact` | no |
| `aggressive` / lab (lab-allowlist only) | `full` (exfil/persist) | `lab-allowlist` | off | `plaintext-lab` | yes |
| `pre-investment-dd` | `full` (signed 1-off scope required) | `strict-authorized` | on | `encrypt-redact` | if authorized |
| `continuous-devsec` / `vc-portfolio-monitor` (prod) | `read-only` | `strict-authorized` | on | `encrypt-redact` | no |
| `remediation-verification` | `read-only` (replay known vectors) | `strict-authorized` | on | `encrypt-redact` | no |
| `passive` / `standard` | `read-only` | `strict-authorized` | on | `encrypt-redact` | no |
| `stealth` | `read-only` | `strict-authorized` | on | `encrypt-redact` | passive jitter only |
| **unset / unknown (default)** | **`none`** | **`strict-authorized`** | **on** | **`encrypt-redact`** | **no** |

> **Owner decision to confirm:** `crown` (the default that *can* point at customer prod) is capped at
> `lateral` — it chains pivots *within authorized scope* but never exfils/persists. The full crown-jewel
> demo (DB dump → exfil) runs under `aggressive`/lab (benchmark targets) or `pre-investment-dd` (signed
> scope). This preserves the moat narrative on lab/DD while keeping prod safe. Adjust the `crown` row if
> you want prod crown scans to reach `full`.

**Two non-negotiables the profile only *parameterizes* — they must be BUILT regardless:**

1. **Effective capability = min(profile ceiling, per-engagement authorization).** `full` only reaches
   `full` against the **lab-allowlist** (`aggressive`) or under an explicit **signed one-off scope**
   (`pre-investment-dd`). The lab-allowlist is a concrete, operator-controlled file of lab hosts/CIDRs
   checked at `resolve_policy` time; a `full` profile **refuses to start** if the target is not on it
   (fail-closed, not advisory). Profile selection alone never authorizes destructive pivots on
   un-allowlisted hosts.
2. **The enforcement chokepoints must exist and DENY on `policy is None`** (a profile sets strictness; it
   can't substitute for the chokepoint). `ScanContext.policy` is a plain dataclass field, so any path that
   builds a context without `resolve_policy` (tests, the Phase-R resume loader, the legacy pipeline)
   yields `None` — every chokepoint must treat `None`/unset as `FORBIDDEN`, never fall through. Invariant
   + test: `permit_*(policy=None) → FORBIDDEN`.
   - `permit_strategy(strategy, policy)` — every block-adaptation / evasion dispatch routes through it.
   - `permit_pivot(target_host, action, policy, scope)` — every H pivot routes through it; lateral move
     to any host not in authorized scope is `FORBIDDEN`; `exfil`/`persistence` are their own destructive
     action classes, forbidden unless `exploitation_ceiling == "full"` AND in scope.
   - `persist_secret(value, policy)` — credentials/tokens stored as fingerprint (sha256 + last4) unless
     `secret_handling == "plaintext-lab"`; raw values (when allowed) go to a separate per-tenant store.

**Storage shape is decided now, enforcement is policy-gated** (the retrofit-avoidance point): the dossier
carries a **required, non-defaulted** `tenant_id` and the path is `data/pti/<tenant_hash>/<target_hash>/`
**from day one**. `tenant_id` is derived from the **authenticated engagement / API credential at the
trust root — never a request field or operator free-text** (otherwise the validator is decorative and
provides no isolation). The PTI store must **refuse to read across a tenant boundary it wasn't opened
for** — the `model_validator` alone does not enforce isolation. In `aggressive`/lab mode
`tenant_id == "__local__"` and isolation/encryption are no-ops — but the field, path, and store-level
tenant guard exist, so prod isolation is "fill the value + flip enforcement," never a schema migration.

## Scope

| ID | Component | Phase | Nature |
|---|---|---|---|
| 0 | Consolidation (memory×2, hypothesis class, model table×3, prioritizer×4-5) | 0 | delete/migrate, **rollback-safe** |
| P | Profile-driven `ScanPolicy` + chokepoints | 1 | **new**, unblocks safe H |
| A | PTI store (absorb both memory systems; add `to_summary`, tenant shape, retention) | 1 | wire + migrate + slim |
| B | Hypothesis DAG as single prioritizer (real API; typed edges) | 1 | wire + collapse |
| V | Verifier hardening (all-severity, `findings[]` chokepoint, PoC gate) | 1 | **harden existing**, not new |
| Sx | Destination-scope chokepoint on shell/exploit path | 1.5 | **new**, hard prereq for H |
| D | Coverage matrix + coverage-gated finish (qualitative report) | 2 | wire |
| H | Post-finding exploitation (policy+scope gated; iteration budget) | 2 | new build |
| E | Block-aware adaptation (via `permit_strategy`) | 2 | wire + chokepoint |
| F | Self-evaluation loop (real `cap=5`; subordinate to V) | 2 | wire |
| I | Ask primitive (verified-safe defaults) | 2 | wire + fix |
| C | Cost routing (folded into `brain` decision-class map) | 2 | demoted |
| R | Scan resume / crash-recovery (versioned, with loader) | 2 | new build |
| Z | Tool-output compression | 2 | small |

**Cut:** PTI distillation lock-in (old "J") and Brain tool-authoring (`author_tool`/`reuse_tool`).
Keep a thin trajectory JSONL for eval only.

## Out of Scope

API DAST / role-matrix / business-logic; fleet/VC optimizations; delta scan, asset discovery, credential
vault, compliance mapping (v2 plan); full multi-tenant SaaS deployment. **Note:** the PTI *schema's*
tenant dimension is in scope (shape now); tenant *operations* (quota dashboards, billing) stay in v2.

## Architecture Statement

```
ScanContext.policy = resolve_policy(profile)            (P; fail-closed default)
ScanAgentLoop
  → PTI.load(tenant_hash, target_hash) → dossier        (A; absorbs AgentMemory + JSON KB)
  → DAG.add(seed nodes from dossier + fingerprint)      (B; sole prioritizer)
  → loop:
      model = brain.model_for(decision_class)           (C, folded — one map)
      think_in_loop(messages + dashboard + DAG + Dossier.to_summary(), decision_class)
      ToolRegistry.dispatch(action)
        → BlockClassifier.inspect → permit_strategy(strategy, policy) → adapt   (E + P)
        → DAG.update_belief(node_id, evidence, edge_kind-aware)                  (B)
        → CoverageMatrix.mark(...)                                              (D)
      on candidate finding (ALL severities, at findings[] chokepoint):
        → Verifier.adversarial_verify(finding) → require PoC artifact            (V; SPINE)
          → confirmed-with-PoC only: persist (redacted per policy), enter report
          → if exploitation_ceiling allows: ExploitationModule.expand()          (H)
              → permit_pivot(host, action, policy, scope) per hop (Sx chokepoint)
              → DAG children: edge_kind="pivots_to" (no prior-propagation)
      every N iters / pre-finish: SelfCritique.run(...) (cap=5)                   (F)
      finish = legacy gates REMOVED + DAG.top_untested() + weighted coverage      (B/D)
  → PTI.persist(verified facts only; secrets fingerprinted)                       (A + P)
  [resume: versioned atomic snapshot per iter; loader on --resume]                (R)
```

---

## Phase 0 — Consolidation, rollback-safe (week 1)

**Goal: one memory, one hypothesis class, one model map, one prioritizer — without an un-rollback-able
cutover.** Deletion is NOT flag-protected by itself, so we **dual-write first, delete later.**

**Task list**

1. **Memory merge — shadow/dual-write, not delete-and-pray.**
   - Add `VXIS_V3_MEMORY` flag (**default off → old `AgentMemory` path stays live**). When on, reads come
     from PTI; writes go to **both** PTI and `AgentMemory` for one release (parity window).
   - Map `ScanMemory` → `Dossier` fields. Migrator `scripts/migrate_agent_memory_to_pti.py`:
     **idempotent** (keyed upsert by `(tenant_hash, target_hash)`, content-hash dedupe of facts),
     `--dry-run`, per-target `migrated_at` + `source_checksum` marker, emits `{migrated, skipped, failed}`
     manifest, re-runnable after partial failure.
   - Re-point the consumers: write site `core/orchestrator.py:735`, read site `brain.py:1770`
     (`recall_similar` → `format_memory_context`, returns a **formatted prompt-fragment string**), the
     `query_scan_memory` tool backend (`memory_tools.py:519`), and the import/injection at `brain.py:68/143`
     + internal `memory.py:187`. Keep tool name + I/O contract identical. The legacy write at
     `orchestrator.py:744` stays, so `VXIS_V3_MEMORY=off` is a true rollback.
   - **Parity test asserts on the formatted prompt fragment** (byte/semantic-equivalent), not just
     fact-set equality, since `brain.py:1770` returns formatted text. Exit grep covers `AgentMemory`,
     `remember_scan`, AND `recall_similar` call sites.
   - **Secret/tenant safety in the dual-write window:** the `AgentMemory` leg predates the policy layer
     (no `persist_secret`, no tenant dimension). Either gate the `AgentMemory` write behind `persist_secret`
     too, or forbid secret-bearing facts on the `AgentMemory` leg during the window — do **not** dual-write
     raw exploitation secrets to the un-tenanted legacy store. (Implies the `persist_secret` chokepoint from
     Component P must be available before exploitation data is dual-written.)
2. **Delete `AgentMemory` only in a later phase** (Phase 2 cleanup) once prod dossier parity is measured.
   Provide a reverse migrator or a documented data-loss-on-rollback note. Until then `VXIS_V3_MEMORY=off`
   is a real one-flag rollback.
3. **Hypothesis de-collision.** Rename `Hypothesis`→`HypothesisNode` in `dag.py` **and** all in-file refs,
   forward-ref strings, and `agent/hypothesis/__init__.py` exports. Exit grep: `class Hypothesis\b`
   returns exactly one (don't false-positive on `HypothesisOutcome`/`HypothesisFilter`).
4. **Model map merge.** Delete `cost_router.ROUTE_TABLE`; keep `brain._model_role_for_decision_class` as
   the sole map; keep `CostReport`. Reconcile verify model: pin verifier role explicitly (see V).
5. **Prioritizer collapse.** Author the field-level mapping table for `vector_candidates` + `scan_todos` +
   `branches`(`BranchState`) + control-state. Add the absorption shim (seeds→roots, branch edges→DAG
   edges, `BranchState` rich fields→a side-table keyed by `node_id` or explicit delete). The legacy
   finish helpers (`_blocking_finish_branches`, `_remaining_high_yield_family_candidates`) are **not 5
   isolated branches** — they have **10+ call sites woven through `scan_loop_decision_policy.py`**
   (~lines 22, 374, 792, 872-874, 2149-2197) plus `scan_loop_actions.py:1097` and `scan_loop_run.py:1467`.
   This is a **migration** (replace each call site with a DAG query), not a delete. Exit check: zero call
   sites remain AND the DAG query covers each replaced behavior.
6. **Docs:** `docs/superpowers/CONSOLIDATION.md` (table schema: per-system `old → new home, consumers
   re-pointed, removal commit, grep-guard`), and the wiki ADR (see Cross-cutting).

**Phase 0 exit:** `VXIS_V3_MEMORY=off` restores old path (proven rollback); dual-write parity test green;
one `HypothesisNode`; one model map; legacy gate helpers unreferenced; full suite green;
`VXIS_V3_PTI=0` isolation still works (NB: the knob is the env var, there is no `--no-pti` CLI flag).

Commit prefix: `phase-0:` (CLAUDE.md sanctions `phase-N:` / `feat(scope):` — do **not** use `refactor()`).

---

## Phase 1 — Policy + PTI + DAG + Verifier (weeks 2–5)

### Component P — ScanPolicy + chokepoints

1. `src/vxis/agent/policy/scan_policy.py` — `ScanPolicy` model + `resolve_policy()` that reads
   `config.active_profile` (normalized), with a row for **every** `_default_profiles()` entry; unknown →
   fail-closed default.
2. Add **typed** `policy: ScanPolicy | None` and `scope: ScopeEnforcer | None` fields to the `ScanContext`
   dataclass (`pipeline/context.py`) — not monkey-patched `# type: ignore` attributes. Resolve + attach in
   `ScanPipelineV2.run()`.
3. `permit_strategy` / `permit_pivot` / `persist_secret` chokepoints — **each returns `FORBIDDEN` when
   `policy is None`**. Lab-allowlist file (operator-controlled) checked in `resolve_policy`; `full` profile
   raises at scan start if target not on it.
4. Unit tests (all deterministic, CI-safe): default = most restrictive; `policy=None` → FORBIDDEN at every
   chokepoint; `aggressive` = full but refuses to start off the lab-allowlist; prod profiles refuse
   lateral/exfil/evasion; `crown` permits in-scope lateral but refuses exfil/persist; `min(ceiling,
   authorization)` enforced. (Scope-leg enforcement is stubbed here; the real scope check lands in 1.5 —
   Phase 1 `permit_pivot` tests cover the policy-ceiling leg only.)

### Component A — PTI (wire + migrate + slim + bound)

1. Add **`Dossier.to_summary(token_budget)`** — structured excerpt (top stack/defenses by recency,
   last-scan delta, confirmed-findings-to-re-verify) with **field selection before serialization**
   (today `_safe_summary` falls back to `str()[:N]`). Test: summary length stays bounded as
   `findings_history`/`payload_library` grow.
2. Add **required, non-defaulted** `tenant_id` to `Dossier` (derived from the authenticated engagement
   trust root, not a request field); path `data/pti/<tenant_hash>/<target_hash>/`. A `model_validator`
   alone does NOT enforce isolation — the **store must refuse to read across a tenant boundary it wasn't
   opened for** (open `PTIStore(tenant_hash=…)`; reject loads of any other tenant's path). Tighten
   `extra="allow"` on PTI models (lands before H) so H can't silently dump unvalidated cred blobs.
3. **Retention/quota:** cap `scans/` + `trajectories/` to last N per target (age-based); per-tenant disk
   quota + defined failure mode (reject vs evict-oldest).
4. Wire `ScanContext.pti`; load at start, **persist verified-only** at end; secrets via `persist_secret`.
5. Inject `Dossier.to_summary()` into `_build_scan_dashboard()` (`scan_loop.py:347`).
6. Aging: verifier re-checks facts older than N scans before they influence priors.
7. Trim trajectory to a thin eval log; **keep `apply_privacy`** (host/URL hashing) and extend redaction to
   `outcome_evidence`; delete distillation schema (`schema_version` ceremony) + its tests. Tighten
   `query_pti(...) -> list[Any]` to a typed union and `hash_sensitive_context` off `Any -> Any`.
8. Integration test: scan a fixture twice; scan #2 loads non-empty dossier; dashboard shows excerpt.

### Component B — DAG as single prioritizer (real API + typed edges)

1. **Add the genuinely-missing methods** (the original names don't exist): a seeding entrypoint and a
   `prioritize()` over `top_untested()`. Reuse existing `add/update_belief/prune_dead/top_untested/query/
   to_summary`. Seed at iter 0 after `fingerprint_target` (optionally via
   `HypothesisGenerator.from_finding()`).
2. **Add `edge_kind: Literal["refines","pivots_to"]`** to child edges; `update_belief` skips
   prior-propagation across `pivots_to` (a pivot's feasibility is independent of its parent's confirmation)
   — required before H, or H corrupts `top_untested()` ordering and the coverage gate.
3. Wire `prioritize()` into the per-iter decision; dashboard `to_summary()` replaces the vector-candidate
   block (no fallback list). Prune `<0.05`; cap 100 nodes / ≤5 children.
4. **Belief honesty + canonical status vocabulary (resolve once, before any report partial is built):**
   the single sanctioned status set is **`untested / testing / confirmed / refuted / inconclusive`**.
   Map the verifier's `CONFIRMED/UNCONFIRMED/REFUTED` onto it (`UNCONFIRMED → inconclusive`). Reports
   render these words bilingually (`confirmed→확인됨`, `refuted→반증됨`, `inconclusive→미확정`, …) and
   **never** surface numeric priors/probabilities (priors are heuristic, documented as such in `bayes.py`;
   dashboard-only if labeled "heuristic").
5. Persist `hypothesis_history` to PTI. Report "Hypotheses Tested" section (see report rules below).
6. Integration test (Juice Shop): ≥10 nodes, ≥50% confirmed/refuted, none stuck >40 iters.

### Component V — Verifier hardening (THE SPINE — harden existing, not new build)

The verifier already exists (`verifier_tools.py` + gate `scan_loop_run.py:489-618`). Close the two real
gaps and add the PoC code-gate.

1. **Lower the severity gate from high/critical to ALL findings** (`scan_loop_run.py:496`) — mediums/lows
   currently bypass verification, breaking zero-FP.
2. **Move the gate from the `report_finding` boundary to the single `findings[].append` chokepoint** so
   skill auto-reporting / sticky re-injection can't bypass it.
3. **PoC-artifact code gate:** no reproducible PoC (request/response pair or script) ⇒ downgrade to
   `unverified`, excluded from report. Build on the existing `_looks_like_thin_claim_only` heuristic.
3b. **Redaction is a property of the `findings[].append` chokepoint, co-located with verify** (not a
   separate dossier-only task). PoC request/response pairs contain the recovered secret/token and flow
   `findings[]` → `ReportData.findings` → HTML; `report/generator.py` has **no redaction today**. When
   `policy.secret_handling != "plaintext-lab"`, redact secrets out of `Finding.evidence`/PoC at the
   chokepoint before they reach either the dossier or the report (reuse/broaden `scope/pii_detector.py`;
   feed it the fingerprints captured by `persist_secret`). Test: a confirmed cred-extraction finding's
   report HTML contains the fingerprint, not the raw secret.
4. **Bound cost:** dedupe candidates before verify (don't re-verify same surface/vector signature);
   gate the optional N-refuter majority (`VXIS_VERIFY_REFUTERS`, cheap models) **behind a confidence band**
   (borderline verdicts only). Emit `verify_calls` / `verify_confirmed/rejected` telemetry.
5. **Model honesty:** `hybrid_config` defaults VERIFIER == DIRECTOR == `claude-sonnet-4-6`; director may
   resolve to `gpt-5.4` per env. Either accept sonnet for verifier or explicitly pin a stronger model and
   own the cost — do not claim "strongest model" without setting it.
6. PoC re-execution routes through Hands/X-Ray/Controller/Finding (no raw httpx).

### Phase 1 Exit Criteria

- `VXIS_V3_MEMORY=off` is a working one-flag rollback; dual-write parity test green; one `HypothesisNode`,
  one model map; legacy finish-gate helpers unreferenced.
- DAG is sole prioritizer; `Dossier.to_summary()` bounds context as the dossier grows.
- Verifier gates **all severities** at the `findings[]` chokepoint; every CONFIRMED finding carries a PoC.
- PTI carries `tenant_id` + retention; secrets fingerprinted unless `plaintext-lab`.

---

## Phase 1.5 — Destination-scope chokepoint (week 5–6) — HARD PREREQUISITE FOR H

Today the exploit path is an **unrestricted shell** (`shell_tools.py:10-14`, "UNRESTRICTED by design");
`egress_policy.evaluate_shell_egress` only forces Ghost proxy use, it is **not** a destination filter. And
the supposed gate, `ScopeEnforcer`, is **not load-bearing today**: it is never constructed or called in
any scan/shell/network path; its only callers (three MCP tools, `mcp_server.py:448-461`) are **broken**
(wrong args → `TypeError`); its API is **URL-shaped** (`check_action(method, url, body, headers)`,
`enforcer.py:110`), not `host:port`; and — worst — with the default empty `in_scope_domains` it
**ALLOWS ALL hosts** (`enforcer.py:59` skips the host check), i.e. it currently fails *open*. So Phase 1.5
is "fix + wire + extend `ScopeEnforcer`," not "call the existing gate." **H cannot merge until this lands.**

1. **Fix and wire `ScopeEnforcer`:** repair the broken MCP callers; construct a `ScopeEnforcer` from
   `ScopeConfig` and attach it to `ScanContext.scope` at scan start (nothing loads scope into the agent
   path today). Add a `check_destination(host, port)` method (or a host→synthetic-URL adapter) since shell
   tools have a host/port, not a URL.
2. **Make empty scope fail-closed:** empty `in_scope_domains` must **DENY**, not allow-all. Add a concrete
   multi-host authorization field so a pivot's "in scope" is well-defined (single-`target` scope cannot
   express lateral targets today).
3. Route every shell/exploit destination through `permit_pivot` → `ScopeEnforcer` before execution.
   Out-of-scope host = `FORBIDDEN` (not approval-gated).
4. **Add `data_exfiltration` / `persistence_install` / `lateral_move` as real scope `ActionPolicy`
   classes** (today they exist only as agent-ID strings, and `check_action` only consults destructive
   classes via `_DESTRUCTIVE_URL_HINTS` substring matching that won't fire on shell commands — so they
   need an explicit invocation path, not just dict entries). Forbidden unless `exploitation_ceiling ==
   "full"` AND host in scope AND (non-lab) explicit per-engagement authorization. `auto_approve` may
   **never** approve these classes.
5. Tests (deterministic, no LLM): empty scope → DENY; in-scope pivot permitted; out-of-scope host refused;
   prod profile refuses exfil/lateral; lab profile permits against allowlist only; broken-MCP-caller
   regression fixed.
6. **CI enforcement of the prerequisite:** the cassette tier fails H's flag-on path if `permit_pivot` is
   not invoked on every shell/exploit destination — so "H cannot merge before 1.5" is a test, not a comment.

Commit prefix: `feat(scope):`.

---

## Phase 2 — Autonomy + Exploitation (weeks 7–12)

### Component D — Coverage matrix + coverage-gated finish (wire; qualitative report)

1. Tag high-value surfaces (admin/auth/payment) in dossier + heuristic. Wire `CoverageMatrix` into state.
2. Finish gate (replacing the deleted legacy gates): high-value surfaces 100% probed across applicable
   vectors; all `prior≥0.5` hypotheses confirmed/refuted; **weighted** coverage (Σ prior×surface_value),
   not raw cell %.
3. **Report shows coverage qualitatively, not a raw %** ("All high-value surfaces (auth/admin/payment)
   probed across N vector classes; M hypotheses resolved"), bilingual. Dashboard may show the number
   labeled "high-value surface coverage."
4. Integration test: untested high-value surface ⇒ cannot finish.

### Component H — Post-finding exploitation (policy + scope gated)

1. `src/vxis/agent/exploit/module.py` — `expand(finding, dossier, policy)` adds DAG `pivots_to` children
   per MITRE ATT&CK pathway, **each hop through `permit_pivot`**; respects `exploitation_ceiling`.
2. `src/vxis/agent/exploit/pathfinder.py` — ShadowGraph-style shortest-path over PTI surface + confirmed
   findings + credential **references** (not raw secrets). Clean-room reimplementation (concept only).
3. Reserve `post-exploit` coverage namespace (only meaningful once H ships).
4. **Exploitation iteration budget** (distinct from the 100-node cap): max post-exploit children testable
   per scan + chain-depth limit, so H can't manufacture work that blows the 300-iter cap; treat
   post-exploit children as lower finish-priority so they don't hard-block finish.
5. Report: reuse the existing `attack_chains` / `_attack_paths.html` (do **not** add a parallel renderer);
   add MITRE tags per hop, bilingual.
6. **Deterministic unit tests** (CI-safe): `expand()` adds the expected child set per finding-type;
   `pathfinder` returns the known shortest path over a fixture graph; **prod-profile refuses destructive
   pivot**. Live crown-jewel chain only in the periodic live tier.

### Component E — Block adaptation (via `permit_strategy`)

1. Wire classifier hook → `permit_strategy(suggested_strategy, policy)` → Ghost (`src/vxis/ghost/`) /
   skill mutation / browser. **Single chokepoint, fail-closed**; evasion only if `evasion_allowed`.
2. Honeypot suspicion forces passive-only **independently of policy**; confidence ≥0.7 before any switch;
   verifier re-checks suspected honeypot before escalation.
3. PTI `defenses`/`bypasses_known` write-back. Ghost/Tor additionally gated by a per-engagement
   "evasion authorized" scope flag (customer authorizing a scan ≠ authorizing source-IP rotation).
4. Tests: mock-WAF bypass round-trips to PTI; prod profile refuses Tor-rotate.

### Component F — Self-evaluation (real cap; subordinate to V)

1. **Implement the `cap=5` counter** in `v3_maybe_run_self_critique` before F becomes LLM-backed; exempt
   the deterministic gap-eval from the cap; make the force-on-finish path idempotent (skip if no DAG/
   coverage delta since last critique).
2. F finds **recall gaps**; it must **not** relax the V precision gate to "fill gaps."
3. Test: seeded unblocked high-prior hypothesis forces continuation (deterministic). Drop "≥1 real gap
   per scan" as a CI gate (keep as a tracked metric — "real" isn't assertable).

### Component I — Ask primitive (verified-safe defaults)

1. **Fix `assumed_safe_default`:** for any mutating/aggressive decision class, `default_when_skipped` must
   resolve to the **non-action/abort** branch (enforced in `enqueue`/validator, not by naming). Under a
   prod policy, asks tied to aggressive strategy default to refuse. Rename the asserted field to
   `auto_resolved` + a separate `verified_passive` bool only set when the default was checked passive.
2. Wire dashboard endpoints; Slack/email notifier; "Operator Decisions" report section flags cap-hit /
   timeout auto-resolutions explicitly ("10건 한도 초과 자동 처리|||..."). Add a `resolution_reason` field.

### Component C — Cost routing (folded, demoted)

`think_in_loop(decision_class)` resolves via the single `brain` map; default cheaper role on ambiguity;
verifier/critique pinned. Telemetry: `llm_cost_usd`, `llm_cost_per_finding` (net of verification),
budget-breach event. Target ≥40% cost/finding drop **measured net of the verifier's added calls** — add a
CI assertion that fails if verifier cost share exceeds a budget fraction.

### Component R — Resume / crash-recovery (versioned, with loader)

1. Add `from_dict` loaders (only `to_dict` exists today). `src/vxis/agent/resume/snapshot.py` — atomic
   (temp + replace) per-iteration snapshot of `ScanLoopState + DAG + coverage + PTI delta`, **stamped with
   `state_schema_version`**.
2. On `--resume <scan_id>`: refuse (don't silently load) a mismatched version → fresh-start + logged
   warning (Phase 0 renames types, so this WILL happen across deploys). Delete snapshot on clean
   completion; GC orphans older than N days.
3. **Coordinate with the trajectory write** so disk is hit once per iter, not twice (buffer trajectory).
4. Operator surface: dashboard line + scan-state badge (running / crashed-resumable / resumed), bilingual;
   report metadata notes "resumed from iteration N".
5. Tests: kill mid-run → resume continues without redoing confirmed work; **torn/partial snapshot falls
   back to prior good snapshot**; round-trip byte-equivalence of DAG/coverage/PTI-delta.

### Component Z — Tool-output compression

Compress only outputs destined to **persist across iterations** (large recon dumps), Haiku-class, raw
preserved in evidence store; threshold sized so compression cost < multi-iter context savings;
**exclude credential material from the "preserve every artifact" instruction** (route through redactor).
Test against a stubbed compressor; assert raw copy byte-identical, injected copy shrank.

---

## Benchmark & CI Strategy (3 tiers — the league is a spec today, not a runner)

`src/vxis/scoring/benchmark_league.py` is a declarative manifest; `benchmark.py` runs once per target;
there is no multi-run/variance executor, and its `stability` metric is **completion rate, not cross-run
variance**. LLM nondeterminism makes a live per-merge "zero-FP" gate inherently flaky. **This whole
section is a BUILD, not a config tweak** — see the gap callout below. Target shape:

| Tier | Frequency | Blocking? | What it actually catches |
|---|---|---|---|
| **Deterministic (cassette)** | every PR | **yes** | regressions in *our code* given a **recorded** model verdict: PoC gate loosened, severity filter broken, scope chokepoint bypassed, ScanPolicy mis-resolved, bilingual split, finish-gate math. The pure-deterministic gates (ScanPolicy, scope, severity filter, `_looks_like_thin_claim_only`, PoC code-gate, finish-gate math) need no LLM at all; the verifier's CONFIRMED/REFUTED **verdict is LLM-driven** so it is replayed from a recorded cassette. `@pytest.mark.live`-excluded; no API keys in this job. |
| **Live trend** | nightly during active phases (weekly when stable) | no (alarm) | model/prompt **drift** + cost trend on 1–2 live targets. Cannot be caught by cassettes. |
| **Full live league** | per phase-merge to main / release | **yes** | end-to-end recall/precision/cost on the full league incl. clean-control = 0 CONFIRMED criticals; multi-run (K≥3) mean+stdev. |
| **Holdout** | quarterly (v2) | scored only | overfitting check on a never-trained target. |

**Reality gap (none of this infra exists yet — treat as real build work, not config):**
- There is **no cassette substrate** (no `vcr`/`pytest-recording` dep, no `live` pytest marker, no
  regeneration script), and `.github/workflows/benchmark.yml` **still runs a full live-LLM scan on every
  PR to main** with real API keys + a Docker Juice Shop service. **Phase 0 deliverable:** split
  `benchmark.yml` into a cassette PR job (no keys, no Docker) + a nightly/phase-merge live job (the current
  job, moved off the PR trigger); register the `live` marker in `pyproject.toml`; add `-m "not live"` to
  the cassette job. Acceptance check: the PR workflow has no `ANTHROPIC_API_KEY`.
- The **multi-run/variance harness** (K≥3, mean+stdev, baseline delta-vs-stdev, seed rotation) is its own
  multi-day build — **lift it to a named Phase 0.5 item**, not a buried Phase 0 line, with its own exit
  test ("same target ×3 → mean+stdev + delta-vs-stdev verdict on a fixture"). Until it exists, "CI-blocking
  league gate" is fiction.
- **Cassette regeneration is a real tool**, not a one-liner: record-mode (live API) + secret-scrub of
  fixtures + stable request→response keying that survives prompt edits. Row V rewrites the verifier
  prompt and C/F change routing, so cassettes WILL be invalidated often; the regen tool must be genuinely
  one command and reviewers must re-run it on prompt-touching PRs or the tier silently tests stale behavior.

## Telemetry / Observability (was missing)

The sink already exists: `scan_loop_actions.py:1028` builds the `telemetry` dict, `:1137` assigns it to
`snapshot["telemetry"]`, `:1141` emits `control_plane` to the dashboard. **Add keys to that dict** (don't
reinvent a sink): `coverage_pct`, `finish_blocked_reason`, `verifier_confirmed/rejected/reason_histogram`,
`verify_calls`, `llm_cost_usd` + per-iter budget-breach event, `critique_runs/gaps_filled`. Add an
"expected-nonzero verifier activity" alarm off `verify_calls`. Ops must be able to answer "why didn't this
scan finish?" (`finish_blocked_reason`) and "why did cost spike?" from telemetry.

## Cross-cutting Tasks (each attached to a phase exit + commit prefix)

- `docs/superpowers/CONSOLIDATION.md` (Phase 0 exit) — the merge/deletion ledger.
- **Wiki (repo convention — `wiki/decisions/` ADRs, `wiki/entities/modules/` 1:1):** new ADRs
  `011_v3_consolidation.md` (DAG-sole-prioritizer + memory merge), `012_verifier_spine.md`,
  `013_profile_scan_policy.md`; concept page for adversarial verification; module pages for `pti/`,
  `policy/`, `verify/`, `exploit/`, `resume/`. Mandatory frontmatter (`when_to_read`, `code_anchors`).
- Fix path slips in **CLAUDE.md** and ARCHITECTURE/PHASE_STATUS/FEATURES: report module is
  `src/vxis/report/generator.py` (`ReportData:60`, `generate_html_file:325`), Ghost is `src/vxis/ghost/`,
  isolation knob is `VXIS_V3_PTI=0` (no `--no-pti`), models resolve through the `brain` map.
- New report sections (Hypotheses Tested, Attack Chains, Operator Decisions, coverage) each need: a
  `ReportData` field + a Jinja partial under `src/vxis/report/templates/partials/` + registration in the
  profile template, and must render every human-facing string as `"English|||한국어"` through the
  `bilingual` filter (test: no `|||`-free English in the KO column; status words mapped, e.g.
  `confirmed→확인됨`). Commit prefix for docs: `feat(docs-v3):`.
- The v3 dashboard block (`scan_loop_v3.py:288`) operator-facing labels → bilingual.

## Success Criteria

**Phase 0** — `VXIS_V3_MEMORY=off` rollback proven; dual-write parity green; one `HypothesisNode`, one
model map, legacy finish-gate helpers unreferenced; multi-run harness exists.

**Phase 1 (Policy+PTI+DAG+Verifier)** — default profile fail-closed; benchmark profile full only vs lab
allowlist (test); DAG sole prioritizer; `Dossier.to_summary()` bounds context; verifier gates **all
severities** at `findings[]`, every CONFIRMED has a PoC; **cassette clean-control gate = 0 CONFIRMED
criticals (CI-blocking)**; PTI tenant shape + retention live.

**Phase 1.5** — out-of-scope pivot refused; prod profile refuses exfil/lateral (tests).

**Phase 2** — `chain_depth_mean/max` increase vs Phase 1 (recorded baseline, delta > measured stdev,
pinned `compute_chain_depths` branch); coverage gate blocks finish on untested high-value surface; block
classifier IDs Cloudflare/Akamai ≥90% on fixtures; F cap=5 enforced (no infinite loop); resume continues a
killed scan + falls back on torn snapshot; `llm_cost_per_finding` ↓≥40% **net of verification**; full live
league (K≥3) passes per phase-merge; **(Z)** tool-output compression keeps the raw evidence-store copy
byte-identical, shrinks only the injected copy, and excludes credential material.

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Phase 0 deletion un-rollback-able | `VXIS_V3_MEMORY` default-off + dual-write parity window; delete only after prod parity; reverse migrator or documented loss note |
| Two memory systems diverge | merge re-points all 3 consumers; exit grep covers `AgentMemory`/`remember_scan`/`recall_similar` |
| Migrator partial failure / non-idempotent | keyed upsert + content-hash dedupe + marker + dry-run + manifest |
| Three prioritizers persist as "compat" | field-level mapping table; delete legacy gate helpers; zero-call-site exit check |
| **H exfil/lateral on customer prod** | Phase 1.5 scope chokepoint is a hard prereq; `permit_pivot` forbids out-of-scope hosts; exfil/persist forbidden unless `full` + signed scope; `auto_approve` can't touch destructive classes |
| **Cross-tenant dossier leakage** | `tenant_hash` in path + `tenant_id` validator from day one; secrets fingerprinted |
| Plaintext secrets at rest | `persist_secret` fingerprints unless `plaintext-lab`; PoC artifacts + `outcome_evidence` redacted on write |
| Verifier too strict → recall drop | tune refuter band; precision gate hard, recall gate comparative |
| Verifier cost unbounded (every candidate) | dedupe candidates; refuters only on borderline; cost-share CI assertion |
| H children blow 300-iter cap | exploitation iteration/depth budget; post-exploit children lower finish-priority |
| Self-critique unbounded once LLM-backed | implement `cap=5` counter + idempotent force path before converting F to LLM |
| PTI dossier unbounded context | `Dossier.to_summary()` with field selection; retention caps |
| `assumed_safe_default` unsafe | non-action default for mutating classes; `verified_passive` bool; report flags auto-resolutions |
| Live LLM gate flaky | cassette tier blocks per-PR; live league blocks only per phase-merge (K≥3 variance) |
| AGPL contamination on borrowed (Strix/Metatron/PentestAgent) | R/H-pathfinder/V/Z are clean-room from published concept only; no upstream source consulted; behavior validated by our tests |
| Belief priors oversold | documented heuristic; reports use status words, no probabilities |
| Resume schema drift across deploys | `state_schema_version` stamp; refuse-and-fresh-start on mismatch; snapshot GC |
| ScopeEnforcer fails *open* (empty scope = allow-all) + broken/un-wired today | Phase 1.5 makes empty scope DENY, fixes broken MCP callers, constructs+attaches scope into the loop, adds `host:port` check; CI cassette fails H if `permit_pivot` not invoked |
| Benchmark "CI gate" is fiction (no cassette substrate, live-on-PR, no variance harness) | Phase 0 splits `benchmark.yml` + builds cassette substrate + `live` marker; Phase 0.5 builds the K≥3 variance harness; until then no per-merge gate is claimed real |
| Default `crown` profile silently neutered (no policy row) | Policy table covers every `_default_profiles()` entry; `resolve_policy` keys on normalized `active_profile`; chokepoints DENY on `policy=None` |
| Tool-output compression drops finding evidence / leaks creds | raw copy byte-identical in evidence store; compress only persist-across-iter outputs; exclude credential material (route through redactor) |

## Beyond v3 — Future Components (G, K only; H is now in v3)

**G — Cross-target Knowledge Graph.** Meta-learning above PTI. **Trigger:** ≥50 dossiers OR first VC
portfolio sign-on. PentestAgent's ShadowGraph (shipped in-v3 as H's pathfinder) proves the per-target
version; G generalizes cross-target. Reserve `data/kg/` only at trigger time (don't let it shape v3 schemas).

**K — Multi-agent swarm.** v3 stays single-Brain + routing (lower ops cost; Strix owns the swarm lane).
**Trigger:** single-Brain fails a specific league target after 3 critique cycles. Forward-compat:
`brain` map abstracts dispatch; trajectory carries `decision_class`/`model_used` (add `agent_id`,
additive); DAG ops idempotent → contention = merge-with-priors.

**Parked:** adversarial self-play, multimodal screenshot→DOM, live exploit-DB ingestion, MITRE tree viz.

## Execution Handoff

1. **Phase 0 first** (rollback-safe consolidation) — mostly delete/migrate, dual-write guarded.
2. Each component gets a sub-plan via `superpowers:writing-plans`, **opening with the Current-State note
   for its module** (cite real symbols/anchors — the original plan's method names don't exist). Use real
   anchors: `_director_decide` (`scan_loop.py:350`), `critic_interval` (`scan_loop.py:116/123`), finish
   branch in `scan_loop_run.py` (~1303-1315; there is no `try_finish_scan()`), `_build_scan_dashboard`
   (`scan_loop.py:347`), `QueryScanMemoryTool` (`memory_tools.py:514`).
3. Execute via `superpowers:subagent-driven-development` — fresh subagent per task, two-stage review.
4. Worktree `.worktrees/cognitive-v3`, branch `cognitive-v3/<component>`.
5. Merge gating: cassette tier blocks per-PR; full live league (K≥3) blocks per phase-merge. **H may not
   merge before Phase 1.5 scope chokepoint.** Phase 2 components behind feature flags.
6. G/K only at their named triggers.

## Relationship to Prior Plans

- **Supersedes the original `2026-06-02-cognitive-engine-v3.md` draft** (this is its in-place rewrite; the
  A–K/J/"beyond v3" taxonomy originates there).
- Layers on [`2026-04-08-phase-a-strix-parity-single-loop.md`](2026-04-08-phase-a-strix-parity-single-loop.md)
  without touching Brain-First.
- Reads from v2 [`2026-06-01-vxis-v2-strategy-and-engine.md`](2026-06-01-vxis-v2-strategy-and-engine.md):
  the league is the measurement scaffold (now 3-tier CI); ScanPolicy reuses v2's profile system; PTI
  consumes asset-discovery output; delta scan pairs with PTI surface lifecycle. The **Verifier spine
  implements v2's zero-FP moat; H implements v2's crown-jewel chain claim; ScanPolicy implements v2's
  safe-for-prod promise.**
- Component C is folded into the `brain` decision-class map (supersedes the Phase E hybrid-brain item).
