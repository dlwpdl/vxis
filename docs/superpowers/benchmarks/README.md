# `docs/superpowers/benchmarks/` — Benchmark Captures

> Measurable data captures for each Phase milestone. Every architectural change must be evaluated against these.
> Generated artifacts are not kept in the working tree; benchmark notes should
> summarize the evidence instead.

## Canonical benchmark targets

Phase A uses **two** fixed Docker-local targets as its "scale" — same target means architecture comparisons are honest:

| Target | URL | Docker image |
|---|---|---|
| Juice Shop | http://localhost:3000 | `bkimminich/juice-shop` |
| WebGoat | http://localhost:8080/WebGoat | `webgoat/webgoat` |

DVWA was dropped during Phase A for laptop resource reasons. Phase B may reintroduce it or add HackTheBox easy boxes.

## Active baseline

### [2026-04-08 — Phase A Baseline](2026-04-08-phase-a-baseline.md)

**Two captures in one file:**

1. **Original Task 1 run** (pre-instrumentation, gpt-5.4-mini) — Juice Shop 10 findings / 311.8s / 824.3 score; WebGoat 5 findings / 163.2s / 812.0 score. This is the "old pipeline at its best" reference.

2. **Instrumented re-run** (post Task 1.5a + 1.5b, worktree-loaded) — Juice Shop 3 findings / 80.2s / 758.8; WebGoat 3 findings / 103.8s / 760.4. Same code, just instrumented. **This is the canonical Phase A baseline** — Task 14/11 must compare against this.

**The measurement that matters most:** `brain_decision_count = 0` on both targets. This is the Brain-First violation smoking gun and the primary metric Phase A must flip.

## Phase A Task 11 result (live, 2026-04-09)

First full end-to-end run of `vxis scan http://localhost:3000` under the new `ScanPipelineV2`:

```
VXIS_BENCHMARK peak_context_bytes=0 llm_call_count=20 brain_decision_count=20 findings_count=0
Scan completed | 81.7s | 0 finding(s)
```

| Metric | Baseline | Task 11 | Verdict |
|---|---:|---:|---|
| `brain_decision_count` | 0 | **20** | 🔥 primary goal met |
| `llm_call_count` | 10 | 20 | +100%, real ReAct |
| Wall time | 80.2 s | 81.7 s | neutral |
| Findings | 3 | 0 | ⚠ tuning gap — Phase B |
| Attack chains | 2 | 0 | ⚠ tuning gap — Phase B |

**Diagnosis of findings = 0**: Brain called `browser_render` 20 times on the same URL — got stuck in `LOOP_PROMPT_ADAPTER`'s "Eyes → browser_render" mapping and never tried `shell_exec` with sqlmap / nuclei. This is a prompt-engineering problem, not an architecture failure. Phase A explicitly scoped this tuning to Phase B.

The scan artifact (log) is captured at `logs/scan_20260409_113147.log` (gitignored).

## Artifact policy

Do not commit HTML reports, raw scan logs, stdout captures, timing files, or
screenshots. Put the important metrics and short excerpts in the benchmark note.

## Benchmark-authoring rules

1. Every new benchmark must capture **all four instrumentation metrics** (`peak_context_bytes`, `llm_call_count`, `brain_decision_count`, `findings_count`) via the `VXIS_BENCHMARK` grep line at scan end
2. Must use the **same model** (`gpt-5.4-mini` for Phase A parity — don't compare across models in the same table)
3. Must note the **git SHA** of the worktree at scan time — reproducibility
4. Must use `PYTHONPATH=<worktree>/src` when running from inside a worktree — otherwise the main repo's code gets loaded instead (see `WORKTREE_README.md`)
5. Must record the **exact CLI invocation** — copy-pasteable for re-run
6. When numbers move significantly, document WHY (prompt change, tool addition, model swap) in a "delta analysis" section

## Task 14 comparison hook

When Phase A Task 14 benchmark lands, it must compare against:
- `brain_decision_count_post_migration >> brain_decision_count_baseline` (primary — 0 → 20+ is success)
- `findings_count_post_migration` — acceptable if reduced (Phase B tuning gap), must not be 0 if `findings_count_baseline > 0` with prompt tuning
- `wall_time` — within 2× of baseline
- `peak_context_bytes` — Phase A currently shows 0 because the v2 shim doesn't populate it (bug to fix in Phase B)
- `llm_call_count` — expected to grow (more Brain iterations = more LLM calls)
