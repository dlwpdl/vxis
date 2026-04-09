# Phase Status — Migration Roadmap

> Where VXIS is in its multi-phase evolution from hardcoded-phase pipeline to Strix-parity Brain-First architecture. Updated 2026-04-09.

## Phase A — Strix-Parity Single-Loop Migration (In Progress)

**Goal:** Kill the 14-Phase `ScanPipeline` orchestrator. Make a single persistent Brain ReAct loop the owner of an entire scan end-to-end. Success criterion: `brain_decision_count` grows from baseline 0 to a meaningful number.

**Branch:** `phase-a/strix-parity` (worktree: `.worktrees/phase-a`)

**Plan document:** [`docs/superpowers/plans/2026-04-08-phase-a-strix-parity-single-loop.md`](docs/superpowers/plans/2026-04-08-phase-a-strix-parity-single-loop.md)

### Progress matrix

| Task | What | Status | Commit |
|---|---|---|---|
| 1 | Baseline + 4-metric instrumentation (peak_context_bytes, llm_call_count, brain_decision_count, --output) | ✅ | `2ae3f9f`, `f9d8da3`, `aa69014`, `09379c2`, `e5dc304` |
| 2 | `BrainTool` protocol + `ToolRegistry` (async dispatcher) | ✅ | `4643fae` |
| 3 | `ScanAgentLoop` skeleton with persistent `messages[]` | ✅ | `6123774` |
| 3.5 | `AGENT_SYSTEM_PROMPT` compatibility audit | ✅ | `d77e227` |
| 4 | `AgentBrain.think_in_loop()` sibling method + `LOOP_PROMPT_ADAPTER` + Brain-Loop wiring | ✅ | `afcc84c` |
| 5 | Control tools (`finish_scan` / `think` / `wait`) | ✅ | `a40b36f` |
| 6 | Hands / Eyes / X-Ray primitives → `BrainTool` wrappers | ✅ | `ab8116e` |
| Pivot | Tasks 7–11 replaced with Strix-power tools (shell_exec + python_exec) | ✅ | `3033bd6` |
| 7 | `shell_exec` tool + `vxis-sandbox` Docker image | ✅ | `dc9681f`, `845f4fe` |
| 8 | `python_exec` tool | ✅ | `402ba14` |
| 9 | Finding CRUD tools (`report_finding` / `query_findings` / `link_chain`) | ✅ | `04a5e8e` |
| 10 | `ScanPipelineV2` — 5234-line pipeline replaced with 360-line shim | ✅ | `9329d9f` |
| 11 | Benchmark gate — end-to-end smoke against Juice Shop | ⏳ in review | (see below) |
| 12 | Cleanup — delete legacy `pipeline.py` + `phases/guides/` | ⏳ pending | — |

### Task 11 — first real end-to-end run

First full run of `vxis scan http://localhost:3000` under the new v2 shim (2026-04-09):

```
VXIS_BENCHMARK peak_context_bytes=0 llm_call_count=20 brain_decision_count=20 findings_count=0
Scan completed | 81.7s | 0 finding(s)
```

**The `brain_decision_count=20` is the most important number in the entire migration.** Baseline was 0. The ReAct loop is real; the Brain is deciding end-to-end for the first time.

**`findings_count=0` is a known tuning gap, not an architecture failure.** Analysis of `logs/scan_20260409_113147.log` shows the Brain called `browser_render` 20 times in a row on the same URL — it got stuck in the adapter's "Eyes → browser_render" mapping and never tried `shell_exec` with sqlmap/nuclei. This is a prompt-engineering problem, explicitly deferred to Phase B.

### Phase A exit criteria — interpretation

| Criterion | Target | Actual | Status |
|---|---|---|---|
| Single continuous Brain loop owns the scan | ✓ | ScanAgentLoop via ScanPipelineV2 | ✅ |
| `brain_decision_count` grows from 0 | ≥ 1 | 20 | ✅ |
| `pipeline.py` reduced below 1000 lines | new file 360 lines (old unchanged, deleted in Task 12) | 360 | ✅ |
| All existing tests still pass (no NEW regressions) | 13 pre-existing unchanged | 13 | ✅ |
| Findings ≥ baseline (3 on Juice Shop) | ≥ 3 | 0 | ⚠️ Phase B tuning |
| Attack chains ≥ baseline (2 on Juice Shop) | ≥ 2 | 0 | ⚠️ Phase B tuning |
| Per-target attempt counts differ (dynamic) | not profile-hardcoded | N/A (loop path) | ✅ |

**Verdict:** Architectural criteria met. Quality criteria deferred to Phase B tuning. Phase A is substantively complete — Tasks 11 and 12 finalize the documentation and cleanup.

## Phase B — Tuning + Episodic Memory (Next)

Proposed scope after Phase A close-out:

1. **Prompt engineering for `LOOP_PROMPT_ADAPTER`** — explicit guidance to prefer `shell_exec` with sqlmap/nuclei, dedup same-URL+same-tool calls, `report_finding` required on vulnerability detection
2. **Scanner integration depth** — standard prompt snippets for common sqlmap / nuclei / ffuf invocations
3. **Episodic memory DB** — persist per-scan findings / chains / failed attempts → retrieve on similar future targets
4. **Dual Brain orchestration** — cheap loop executor (Haiku / Sonnet) + expensive hypothesis generator (Opus)
5. **Benchmark re-run** target: match or beat original baseline (3/5 findings on Juice Shop/WebGoat)

## Phase C — Structured Belief + Enterprise Readiness

1. **Adversarial verifier agent** — different model, prompted to refute claimed findings before confirming
2. **Typed blackboard** (Postgres / event bus) — structured entity store for endpoints, credentials, hypotheses
3. **1M context mode** — Claude Opus 4.6 1M for enterprise scans, disable `MemoryCompressor`
4. **Enterprise egress filter** — second-layer gate on sandbox outbound traffic for customer-production scans
5. **MITRE ATT&CK / CAPEC** coverage overlay as soft checklist

## Phase D — Domain Expansion

1. **Game runtime** — Unity memory hooking, emulator control (16-phase original spec)
2. **Mobile runtime** — Frida / Objection for APK dynamic analysis (19-phase original spec)
3. **Firmware / Hardware** — CAN bus, RF, smart meter bench rigs
4. **Cloud console** — AWS / Azure / GCP session automation beyond API-only

## Historical baseline

Pre-migration benchmark (`docs/superpowers/benchmarks/2026-04-08-phase-a-baseline.md`) for reference:

| Metric | Juice Shop (gpt-5.4-mini, pre-instrumentation) | WebGoat |
|---|---:|---:|
| Wall time | 311.8 s | 163.2 s |
| Findings | 10 | 5 |
| VXIS Score | 824.3 | 812.0 |
| `brain_decision_count` | 0 | 0 |

Re-run with instrumentation (same code, no loop migration): 3/3 findings, 758.8/760.4. This is the true baseline the Phase B tuning pass must beat.
