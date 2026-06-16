# VXIS NOW Roadmap — Resume Checklist

> Created 2026-06-15. **NOW-1 CORE COMPLETE** (1.1 `8e83b00`, 1.2 `c6856b3`, 1.3a `f330023`,
> 1.3b `f34a5ec`, 1.4 CI clean-control gate). Full suite green (2461 passed). Also fixed a
> pre-existing agent-graph logger bug (`a7a8fac`).
> **NOW-1 + adversarial review COMPLETE** (review fixes F1/F2/F3 in `6b46865`; full suite 2473 green).
> **NOW-2 wireable slices DONE (2a/2b/2c/2d) + hardening F1–F6 DONE.** ADR-013
> capability-ceiling enforced at the action boundary (box-mode + evasion + exploitation
> + skill-template governance + secret redaction + injection-approval). Only `permit_pivot`
> (cross-host) blocked on a non-existent executor. Merged to main.
> **Hardening pass (user's 6 findings, recommended order F1→F2→F5→F3; F4/F6 prior):**
> F1 PTI redaction completion `f0e5999`; F2 ceiling governs run_skill `c886d00`;
> F4 policy-token restore + F6 log swallowed v3-reg `08a6a73`; F5 box-mode source-access
> metadata guard `1a523fe`; **F3 injection-approval wired into dispatch `d66aa81`** (this batch).
> **NOW-3 DONE (#1 box-mode, #2 attack-level badge, #3 parallel/serial, #4 verification-rate panel).**
> **2nd review fixes DONE**: policy now active by default (was dormant), readonly is genuinely
> read-only, dashboard dropdown aligned. Full 11-profile TUI parity DONE (`49707c8`).
> **Resume at: NEXT/LATER.** Only NOW-3 residual left = LIVE-scan report proof (user-run scan).
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
- [x] **NOW-1 review round 2** (fp-gate/dedup re-review, `a3dfc...`): dedup verdict-upgrade verified CLEAN. **F4** (`<this batch>`): the 1.4 clean-control gate was a tautology (no-brain fall-through accepted) → now asserts positive deterministic-kill signal per shape (mutation-proven to fail on oracle removal). **F5**: `_should_include_in_report` also excludes REFUTED.
- [ ] **fix-followup (NON-BLOCKING)**: ~~(a) agent-graph temp-file leak~~ DONE (`<this batch>`); (b) **1.3c** DB-regeneration readers filter `status==unconfirmed`; (c) report precision-panel counts UNCONFIRMED that the findings table omits (high/critical only after F1).

## NOW-2 — box-mode hard enforcement + capability-ceiling  (= R8 + ADR-013 + black-box purity)
> De-risked by `now2-dataflow-map` (`w39au4e75`). NOTE: the map's *synthesis* agent was
> blocked by a cyber-safeguard (offensive pivot/exfil framing); plan synthesized manually
> from the recon. ALL NOW-2 work is capability **restriction** (fail-closed safety gates).
> Foundation needed by 2a/2c/2d: an **ambient ScanPolicy ContextVar** (mirror
> `scope/runtime_gate.py` `_ACTIVE`), set after `_resolve_and_attach_policy`, fail-closed None=deny.

- [x] **2b** box-mode hard-enforcement (`<this batch>`): `build_default_registry(box_mode=...)` fail-closed "black"; black-box registers 0 `interaction.code`-backed tools (gated seam `_register_code_surface_tools`, white/grey only); threaded from `kind` (CODE→white else black). Invariant test locks it. **(= user's "블랙박스는 완전히 블랙박스")**
- [x] **2a** evasion gate (`<this batch>`): `_evasion_blocked_by_policy` gates the ghost activation at `scan_pipeline_v2.py:818` — active ScanPolicy with evasion_allowed=False skips ghost (policy-active-only; None=legacy, no regression). TDD green.
- [x] **foundation + 2d** (`24bf8a1`): ambient ScanPolicy ContextVar (`policy/runtime_policy.py`, set after policy attach / cleared in finally) + 3rd fail-closed gate in `tool_registry.dispatch` refusing shell_exec/python_exec when `exploitation_ceiling` < lateral (none/read-only). Policy-active-only; None=legacy. ADR-013 exploitation ceiling now enforced at the action boundary.
- [x] **2c** secret redaction (`<this batch>`): `apply_privacy` (PTI trajectory) now redacts host/query/url when an active ScanPolicy's `secret_handling != 'plaintext-lab'` (via `get_active_policy()`), not only on the `VXIS_TRAJECTORY_PRIVACY=strict` env. policy-active-only; None=legacy. NOTE residual: Evidence.response raw-secret routing through `persist_secret` (touches ADR-006-frozen skills) deferred.
- [x] **2e injection-approval (F3)** (`d66aa81`): the CLI injection gate (`injection_approval_callback`/`auto_approve_injection`) was stored on `ScanPipeline` but **never invoked** — the "인젝션은 마지막, yes/no 승인 후 실행" UI applied zero runtime protection. Now end-to-end: `_INJECTION_DECISION` ambient ContextVar (None=legacy / full / readonly / deny) + `injection_action_blocked()` (only `deny` blocks shell_exec/python_exec + non-passive run_skill); 4th fail-closed dispatch gate (`error="injection_blocked"`); `_resolve_injection_decision()` invokes the callback / honors auto-approve once per scan (fail-closed deny on exception), emits `injection_approval_result`. Policy-active-only; None=legacy. **(distinct from the cross-host `permit_pivot` below.)**
- [x] **NOW-2 hardening** (user's 6 findings, recommended order F1→F2→F5→F3; F4/F6 done earlier): **F1** PTI trajectory redaction completion — output_action + outcome_evidence + header/bearer/query detectors (`f0e5999`); **F2** exploitation ceiling governs `run_skill` attack templates via `skill_blocked_by_ceiling` (`c886d00`); **F4** policy-token restore so nested/SDK/MCP runs can't wipe the outer policy + **F6** `logger.debug` the swallowed optional-v3 tool-registration except (`08a6a73`); **F5** box-mode source-access metadata guard `tool_is_source_aware` + `_enforce_box_mode` (`1a523fe`); **F3** injection-approval (above). Full suite 2526 green.
- [ ] **permit_pivot** per-destination (cross-host) (BLOCKED): no real cross-host executor exists (lateral_move/data_exfil agents are single-target feasibility recon → hypothesis routing). Coarse agent-level spawn gate is possible; true wiring blocked until an H-exec executor exists. Defer.
- [x] grey-box explicit opt-in (`--box {auto,black,white,grey}` CLI flag) (`024b07e`): plumbing done — flag + `_box_flag_to_mode` → `pipeline.run(box_mode=...)`. TUI grey option still withheld until source tools exist (see NOW-3 #1).
- [x] **REVIEW FIXES (2nd external review, 2 High + 1 Med)** — F1/F2/F4/F5/F6 + injection redaction probe verified clean. **#1 policy was DORMANT by default** (gate on VXIS_V3_POLICY/VXIS_V3, never set by cli/main or multi_scan → injection approval never fired, F1/F2/F3 inert): fixed via `ScanPipeline(enable_policy=...)` + `_policy_active()`; CLI single-scan + batch pass `enable_policy=True`; default profile crown so the common scan isn't neutered (`5c5f3bc`). **#2 readonly wasn't read-only** (treated like full): `injection_action_blocked` now refuses exploitation + non-passive skills + mutating HTTP (POST/PUT/PATCH/DELETE) under readonly; GET/HEAD + passive still run; CLI text says BLOCKED not "deferred"; the test locking the no-op was rewritten (`5c5f3bc`). **#3 dashboard dropdown** aligned to TUI labels + crown (`17a1e27`).

## NOW-3 — TUI box/profile/attack-level + live report proof
- [x] **#1 box-mode explicit + enforced** (`024b07e`): `pipeline.run(box_mode=)` + pure fail-closed `_resolve_box_mode` (explicit black wins over kind; invalid → black, never escalates to source); `--box` CLI flag; the TUI web-agent path passes `box_mode="black"` EXPLICITLY and shows "⚫ 박스 모드: 블랙박스 (외부 시점 · 소스 접근 없음)" in the summary. **Honest scope:** white/grey register source-aware tools but `_register_code_surface_tools` is still an empty seam, so NO fake grey/white TUI option is offered yet (would be a no-op). White-box stays the dedicated code-scan category. Profile labels Korean-friendly + `crown` surfaced (`ca4907f`). RESIDUAL: a true FIRST-step black/white/grey selector waits on real source-aware tools.
- [x] **#2 attack-level badge + full profile parity** (`ac553dc`, `49707c8`): `attack_level_badge(profile)` reads PROFILE_POLICY_TABLE → 0–3 rank from `exploitation_ceiling` (●/○ bar) + risk flags (lab-only / evasion-on / approval-required), so the display can't drift from enforcement. Rendered on every agent-wizard execution-permission option ([공격력 ●●○] …) + a "📊 공격 레벨" summary line. **Full parity (`49707c8`):** a 5th quick-pick option "⚙️ 전문 프로필 직접 선택" drills into `_specialized_profile_choices()` — VC 포트폴리오 모니터링, 투자 전 실사, 지속 DevSec, 조치 검증, 컴플라이언스 매핑, 조용한 점검, each badge-labelled. `requires_engagement` profiles (p1-adversary-emulation) excluded (need the `vxis eng`/--engagement workflow, not a TUI pick).
- [x] **#3 parallel vs serial toggle** (`22ca95f`): agent wizard asks 직렬/병렬, sets `VXIS_LOCAL_WORKER_CONCURRENCY` (the agent-graph worker LLM semaphore) — serial=1 (default), parallel=4; `_exec_mode_to_concurrency` fail-safes to serial; shown in the summary.
- [x] **#4 verification-rate panel** (`71d92fb`): bilingual "Verification Rate / 검증율" panel in the report executive summary (CONFIRMED % + per-verdict table), rendered only when `report.has_verdicts`. RESIDUAL (#4 other half): proving a LIVE scan emits this end-to-end needs a real scan run → user-initiated only (CLAUDE.md).

## Model currency + TUI UX (user request 2026-06-16 — de-risked by workflow `wjr4wm2k3`)
- [x] **Hybrid model catalog** (`7af2183`, `a08cd30`): `llm/model_catalog.available_models(provider)` = curated registry (authoritative, offline) + LIVE models.dev (`api.json`, no key, SST/OpenCode community catalog) merged, newest-first, 3-tier fallback live→24h disk cache→bundled. Registry refreshed (`claude-opus-4-8` flagship) + `ModelInfo.release_date`. TUI cloud picker rebuilt: provider-select (key-availability tags) → live model list (source label 라이브/캐시/기본값) → 직접-입력 fallback. Kills the hand-maintained stale lists. Verified live: anthropic 25 / openai 50 / gemini 24.
- [x] **TUI menu full restructure** (`ddffe56`): top level 9→ scan/results/report + 🛠️고급 submenu (산업/클라이언트/플러그인/대시보드); scan wizard AI-auto-first [권장] + advanced types under a separator; "PE 포트폴리오"→"여러 대상 일괄 스캔 (CSV)". Pure choice-builders → unit-tested.
- [ ] RESIDUAL: the duplicated cloud model lists in `agent/brain.py:297-344` + `llm/hybrid_config.py:328-394` still hardcode (internal defaults/validation, NOT user-facing now). Route them through `model_catalog`/`model_registry` too. Also: a Settings → "모델 소스 새로고침" entry to force-refresh the cache.

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
- [x] `agent/tools/__init__.py` silent `except: pass` on optional v3 tool registration → `logger.debug` (F6, `08a6a73`).

## Pointers
- Strategy/why: `wiki/decisions/014_moat_strategy.md` (solid moat ×2; dead-code ×5 marketing guardrail; Strix weaknesses; where-not-to-compete).
- Tactical backlog: `tools/upstream_watch/proposals/2026-06-15.md` (16 items with adopt/defer/reject verdicts).
- NOW-1 detail: `plans/now1_verifier_all_severity.md`.
