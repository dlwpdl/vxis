# VXIS NOW Roadmap — Resume Checklist

> Created 2026-06-15. **NOW-1 CORE COMPLETE** (1.1 `8e83b00`, 1.2 `c6856b3`, 1.3a `f330023`,
> 1.3b `f34a5ec`, 1.4 CI clean-control gate). Full suite green (2461 passed). Also fixed a
> pre-existing agent-graph logger bug (`a7a8fac`).
> **NOW-1 + adversarial review COMPLETE** (review fixes F1/F2/F3 in `6b46865`; full suite 2473 green).
> **Resume at: NOW-2 (box-mode hard-enforcement + capability-ceiling).**
> Fix-followups (non-blocking, tracked below): 1.3c DB-regen filter; agent-graph temp-file leak;
> precision-panel vs findings-table UNCONFIRMED count divergence.
> Decisions locked (user-approved 2026-06-15):
> - Build order: **NOW-1 → NOW-2 → NOW-3**, each `plan → TDD(red-first) → phased commit → /code-review`.
> - moat strategy persisted: `wiki/decisions/014_moat_strategy.md`.
> - 16 upstream-sync proposals loaded: `tools/upstream_watch/proposals/2026-06-15.*` (`decisions.json`: 9 approved / 3 deferred / 4 rejected).
> - Resume = start at NOW-1 / 1.1.

## NOW-1 — Verifier all-severity FP-gate  (full plan: `plans/now1_verifier_all_severity.md`)
ADR-012 Gap 1 closure. The single highest-ROI move (moat bet #1): turns the verifier into a quantifiable FP-rate number.
- [x] **1.1** Consolidated the two drifted gate copies → one `_verify_and_gate()` (both `scan_loop_run.py` inline + `scan_loop_actions._dispatch_report_finding_checked` delegate), behavior-preserving + 6 characterization tests. (`8e83b00`)
- [x] **1.2** All-severity: filter `{high,critical}` → `{critical,high,medium,low}` (informational ungated). REFUTED blocks all; UNCONFIRMED blocks only high/critical to avoid over-suppression. (`c6856b3`)  — NOTE: gate-level cost-bound (LLM only on borderline for medium/low) deferred; verify_finding's deterministic preflight runs first, full LLM otherwise. Revisit if medium/low verify cost is high.
- [x] **1.3** UNCONFIRMED exclude + verdict writeback — two slices. **1.3a** (`f330023`): `_verify_and_gate` stamps `verifier_verdict` onto args → `ReportFindingTool` persists `verifier_verdict`/`verified` (new-finding literal + dedup UPGRADE-ONLY). **1.3b** (`f34a5ec`): `FindingStatus.unconfirmed` + `_build_finding_from_dict` maps verdict→status + `_should_include_in_report` withholds UNCONFIRMED from `ctx.findings` (raw store keeps full corpus). De-risked by the `now1-3-dataflow-map` workflow (caught the dedup-bypass + divergent-path traps).
- [ ] **1.3c** (residual) DB-regeneration readers (cli/main, cli/interactive, cli/multi_scan, dashboard/routes_extra, primitives/output) read `FindingRecord` and don't yet filter `status==unconfirmed`; status is now carried so they *can*. Legacy orchestrator pipeline has no UNCONFIRMED concept. Live HTML report already covered.
- [x] **1.4** CI clean-control gate (`tests/agent/tools/test_verifier_clean_control.py`, `5f44dbf`): 5 benign FP-shapes killed by the deterministic preflight (used_stronger_model=False), clean-control FP-rate==0. Proof that FP control is executable code, not a prompt.
- [x] **NOW-1 review** (Workflow `w2hnivcx1`, 12 agents) → 6 confirmed / 2 refuted. **3 fix-now resolved in `6b46865`**: F1 severity-aware exclusion (medium/low UNCONFIRMED kept), F2 drift-tolerant verdict parse (`_extract_verdict`), F3 attack-chain reconcile (`_reconcile_chains`). One dimension (fp-gate/dedup) failed on 529 → re-running in background (`a3dfc7cbf2ad5df4f`).
- [ ] **fix-followup (NON-BLOCKING)**: (a) agent-graph snapshot temp-file leak on replace() failure → add finally/unlink; (b) **1.3c** DB-regeneration readers filter `status==unconfirmed`; (c) report precision-panel counts UNCONFIRMED that the findings table omits (high/critical only after F1).

## NOW-2 — box-mode hard enforcement + capability-ceiling  (= R8 + ADR-013 + black-box purity)
- [ ] Wire `permit_strategy`/`persist_secret`/`permit_pivot` to read `ctx.policy`, fail-closed (today: 0 production callers; `scan_pipeline_v2.py:707` only attaches).
- [ ] box-mode registry gate: in **black-box**, `interaction/code` tools + `code_to_hypothesis` + repo-mount are all **excluded** (provably can't read source).
- [ ] Invariant/cassette tests: black-box scan ⇒ `interaction.code` imports == 0, no repo mount; an exploit action without a `permit_*` call FAILS.

## NOW-3 — TUI box/profile/attack-level + live report proof
- [ ] `cli/interactive.py`: explicit **⚫ black-box / ⚪ white-box / 🌗 grey-box** as the FIRST wizard step (today: only white-box "code" is explicit; black-box implicit).
- [ ] Unify TUI `PROFILES` with `PROFILE_POLICY_TABLE` (13 profiles incl. **`vc-portfolio-monitor`** = the user's "VC"); render **attack-level badge** from `exploitation_ceiling`/`ceiling_rank` (none→read-only→lateral→full); risk labels (lab-only / evasion-on / approval-required).
- [ ] **Parallel vs serial** toggle for agent scans (`background_worker_concurrency`).
- [ ] Prove a LIVE scan emits a bilingual NCC report at fixture depth; surface verification-rate (CONFIRMED vs REFUTED) as a page-1 panel.

## NEXT
- [ ] Global cost/USD/turn budget governor + honest per-agent attribution (proposal R11).
- [ ] Desktop dynamic confirmation (real `DYLD_INSERT_LIBRARIES` inject) + Windows DESKTOP branch; fix cross-surface synth Finding↔Evidence type bridge + pull into the live scan loop (P8).
- [ ] White-box CODE fusion wired into the live loop (gap#1): `CodeRecon.fingerprint → code_recon_to_hypotheses → push CodeHypothesis into P3 queue → dynamic-confirm → Finding with source line:col`. Run alongside a web target in one scan.

## LATER
- [ ] Converge self-improvement: retrospective `improvement_hints` → structured skill-scheduling bias the decision policy consumes; feed `findings_by_type` into a connected KnowledgeStore.
- [ ] Decide P15 Digital Twin (wire with real per-skill replay, OR drop) ; **DROP P12 Evolution + delete phantom registry entries** ; wire or shelve P13 Biometrics.
- [ ] Fix ADR-001 license record (Strix = **Apache-2.0**, PentAGI/pentest-ai-agents/pentestagent = **MIT** — all non-AGPL).

## Code-hygiene (user research, all verified — fold into the waves above)
- [ ] De-global `_findings`/`_chains` (`finding_tools.py:30`) + `_skill_cache` (`skill_runner.py:32`) → scan-scoped. **Blocks multi-agent / multi-tenant** → do in/before NOW-2.
- [ ] CQS: `_dag_finish_blocking_branches` mutates branch state (`scan_loop_decision_policy.py:46`).
- [ ] `brain.py`: semaphore loop-id dict accumulation (`:115`); `LLM_API_KEY→OPENAI_API_KEY` env side-effect (`:333`, Strix already refactored this — reference).
- [ ] `agent/tools/__init__.py:116` silent `except: pass` on optional v3 tool registration → `logger.debug`.

## Pointers
- Strategy/why: `wiki/decisions/014_moat_strategy.md` (solid moat ×2; dead-code ×5 marketing guardrail; Strix weaknesses; where-not-to-compete).
- Tactical backlog: `tools/upstream_watch/proposals/2026-06-15.md` (16 items with adopt/defer/reject verdicts).
- NOW-1 detail: `plans/now1_verifier_all_severity.md`.
