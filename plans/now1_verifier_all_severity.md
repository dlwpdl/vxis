# NOW-1 Plan — Verifier All-Severity FP-Gate (ADR-012 Gap 1 closure)

> Source: ADR-014 moat bet #1 (단일 최고 ROI). Turns the best LIVE asset (executable
> adversarial verifier) into a quantifiable FP-rate NUMBER — the metric the whole 2026
> cohort claims but none proves in code.
> Workflow: plan(this) → TDD(red→green per phase) → phased commit → /code-review per commit.

## Goal
Close ADR-012 Gap 1: verifier fires on **all reportable severities** (not just high/critical),
through a **single chokepoint**, with **UNCONFIRMED→excluded from report** and the **verdict
written onto the persisted finding**, plus a **CI clean-control gate** (CONFIRMED-critical==0
on a known-clean target).

## Current state (verified in code)
- Two drifted gate copies:
  - `scan_loop_run.py:493-559` inline auto-verify, filter `str(severity).lower() in ("high","critical")` (:496); does NOT block UNCONFIRMED (only tracks); blocking logic separate.
  - `scan_loop_actions.py:738-813` `_dispatch_report_finding_checked(args, require_confirmed=True)`, filter `severity in {"high","critical"}` (:746); blocks non-CONFIRMED when require_confirmed (:794), always blocks REFUTED (:804).
- Real persistence chokepoint `_findings.append(finding)` (`finding_tools.py:883`) is unguarded; any path other than report_finding dispatch bypasses verification.
- Verdict lives only in `state.confirmed_findings/refuted_findings/verdict_counts`; the persisted finding dict has **no `verdict`/`verified` field** → report can't distinguish verified from never-verified.
- `verify_finding` internals (`verifier_tools.py`) are already severity-agnostic (deterministic preflight + LLM refuter) — only the gates restrict it.

## Design
1. **Single chokepoint.** Extract one `async _verify_and_gate(args, *, require_confirmed) -> ToolResult|None` (returns block-result or None=pass) and route BOTH `scan_loop_run.py` and `_dispatch_report_finding_checked` through it. Reconcile the drift (one severity set, one require_confirmed semantics).
2. **Severity policy (bounded cost).**
   - Deterministic preflight (verifier_tools preflight gates): run for **all severities** (critical/high/medium/low; skip informational).
   - LLM refuter: high/critical **always**; medium/low **only when preflight is ambiguous** (borderline) — keeps LLM cost bounded (ADR-012 N-vote-on-borderline spirit).
3. **UNCONFIRMED→exclude.** REFUTED → block (existing). UNCONFIRMED → do NOT ship as a normal finding: mark `verified=false, verdict="UNCONFIRMED"` and exclude from report rendering (demote), per ADR-012 (c).
4. **Verdict writeback.** Add `verdict` + `verified` fields to the finding dict in `finding_tools.py` (report_finding) so ReportData can render a CONFIRMED/REFUTED/UNCONFIRMED trust panel and exclude unverified.
5. **CI clean-control gate.** Test/script asserting `CONFIRMED && severity==critical` count == 0 against a known-clean fixture target → emits the FP-rate metric.

## TDD phases (each = 1 commit + /code-review)
- **P1 — Consolidate (refactor, behavior-preserving).** Characterization tests pin current high/critical block/pass behavior on BOTH paths; extract `_verify_and_gate`; both paths delegate. Green = identical behavior, one code path. Files: `scan_loop_run.py`, `scan_loop_actions.py`, tests in `tests/agent/`.
- **P2 — All-severity.** RED: test that a **medium** finding is now verified (currently unverified). GREEN: drop the `{high,critical}` filter, apply severity policy (#2). Assert low/info path stays deterministic-only (cost guard).
- **P3 — UNCONFIRMED-exclude + verdict writeback.** RED: test UNCONFIRMED medium is excluded from report data and the persisted finding carries `verdict`/`verified`. GREEN: implement writeback in `finding_tools.py` + exclusion in report assembly. Files: `finding_tools.py`, `report/generator.py` (or ReportData builder), tests.
- **P4 — CI clean-control FP-gate.** Add test/script: clean fixture → CONFIRMED-critical==0; surface verification_rate. Files: `tests/` + maybe `scripts/`.

## Risks & mitigations
- **Over-suppression** at low/medium → mitigate: low/info deterministic-only, UNCONFIRMED demote (not hard drop of the data, just exclude from client report); keep a debug log.
- **LLM cost** from all-severity → mitigate: preflight-first, LLM only on high/critical + borderline.
- **Drift reconciliation** (tuple vs set, require_confirmed only in actions) → P1 characterization tests prevent regression.
- **ADR-006 freeze** touches scan_loop surface → justified in commit body (closing an Accepted ADR-012 gap), no new attack logic.

## Out of scope (later NOW slices)
- NOW-2: box-mode hard-enforcement + capability-ceiling chokepoints (same registry-gate mechanism).
- NOW-3: TUI box/profile/attack-level selection + live bilingual report proof.
