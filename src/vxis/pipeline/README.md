# `src/vxis/pipeline/` — Scan Orchestration Entry Point

> The top of the scan stack. CLI instantiates a `ScanPipeline` and calls `run(target)`. During Phase A this module has TWO implementations coexisting — the legacy `pipeline.py` (dead code) and the new `scan_pipeline_v2.py` (live).

## Files

| File | Role | Status |
|---|---|---|
| **`scan_pipeline_v2.py`** (~360 lines) | **LIVE** — Phase A thin shim. Builds `ScanContext`, resets per-scan counters, creates `ScanAgentLoop` + `ToolRegistry`, runs the loop, copies findings/chains from in-memory store into ctx, generates HTML report, computes VXIS score, emits `VXIS_BENCHMARK` line. | Live (CLI imports from here) |
| **`pipeline.py`** (5234 lines) | **DEPRECATED** — legacy 14-phase `ScanPipeline` with `_phase0_foundation` through `_phase18_collective` private methods. Violates Brain-First principle at `pipeline.py:1927-1929` by explicitly bypassing `AgentBrain.think()` for AgentBrain backend. | Dead code — slated for deletion in Task 12 |
| `context.py` | `ScanContext` dataclass — per-scan state container (target, scan_id, findings, attack_chains, vxis_score, duration, deferred_actions, etc.). Also houses `peak_context_bytes` instrumentation. Used by both v1 and v2. | Live |
| `game_pipeline.py` | Game-target pipeline variant (legacy) | Legacy |
| `game_context.py` | Game scan context variant | Legacy |
| `mobile_pipeline.py` | Mobile-target pipeline variant (legacy) | Legacy |
| `mobile_context.py` | Mobile scan context variant | Legacy |

## CLI → pipeline entry

`src/vxis/cli/main.py:437` imports `ScanPipeline`. Phase A switched this single line:

```python
# Before
from vxis.pipeline.pipeline import ScanPipeline

# After
from vxis.pipeline.scan_pipeline_v2 import ScanPipeline
```

The v2 shim preserves the constructor signature exactly so `cli/main.py:590` needs no other changes.

## Phase A `ScanPipelineV2` flow

```
ScanPipeline.run(target, app_context_en="", app_context_ko="", resume_from=None)
  1. Build ScanContext(target, scan_id, …)
  2. Activate ghost (if brain_mode=uncensored or ghost:// trigger)
  3. reset_finding_store()  # clear previous scan
  4. reset_brain_decision_count()
  5. reset_llm_call_count()
  6. registry = build_default_registry()  # 11 BrainTools
  7. loop = ScanAgentLoop(target, registry, brain, max_iters=50)
  8. loop_result = await loop.run()       # ← ReAct here
  9. For each dict in _get_findings():
        ctx.findings.append(_finding_dict_to_finding_object(d, scan_id, target))
 10. ctx.attack_chains = [[fid…] for chain in _get_chains()]
 11. If ctx.deferred_actions: await _run_deferred_gate(ctx)   # enterprise
 12. await _generate_report(ctx)          # NCC-style HTML via ReportGenerator
 13. ctx.vxis_score = _SimpleScore(total=…, grade=…)
 14. Print: VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> …
 15. Return ctx
```

## What the v2 shim does NOT do (vs legacy v1)

- ❌ No per-phase dispatch (`_phase4_cpr`, `_phase5_special`, etc.) — Brain decides dynamically
- ❌ No `_consult_brain_for_phase_vectors` — Brain reads its own context directly via messages
- ❌ No profile-hardcoded attempt counts (legacy had exactly 78 attempts + 11 consultations on every scan)
- ❌ No `_build_batch_brain_decisions` — Brain gets tool catalog, not pre-chosen vectors
- ⚠️ **Temporarily**: no per-phase events for the Rich Live CLI display (emits one `phase_start`/`phase_end` pair for "scan_loop" — TUI shows less granular progress in Phase A)

## Finding dict → Finding object conversion

`scan_pipeline_v2._finding_dict_to_finding_object()` handles the shape mismatch between the in-memory `finding_tools` store (plain dicts) and `vxis.models.finding.Finding` (Pydantic with rich metadata). Safe defaults used in Phase A:

- Severity: string → `Severity.CRITICAL / HIGH / MEDIUM / LOW / INFO` (note: UPPERCASE enum)
- Title / description / remediation: duplicated as bilingual `"EN|||EN"` (Phase B will translate)
- Evidence: single `Evidence(evidence_type="log", content=…)` entry
- CVSS: severity-weighted generic vector (e.g. critical → 9.5)
- CWE: only if explicitly provided

## Critical rules

- **Do NOT modify `scan_pipeline_v2.py` to emit per-phase events** — it defeats the Brain-First principle. Rich Live TUI limitations are a known Phase A acceptance.
- **Do NOT restore `_consult_brain_for_vector` or `_execute_brain_decisions`** from pipeline.py — those are the anti-patterns being killed.
- **Deferred mutation gate plumbing is preserved** (`_run_deferred_gate`) but currently unused (shell_exec bypasses Hands). Phase C will re-wire this at the sandbox egress layer.
- **Report generation is wrapped in try/except** — a broken report doesn't break the scan. Findings are always returned in ctx.

## Deprecation schedule

| File | Deprecation | Removal |
|---|---|---|
| `pipeline.py` | Already dead code (no live imports) | Task 12 (end of Phase A) |
| `game_pipeline.py`, `game_context.py` | Needs new v2 equivalent in Phase D | Phase D |
| `mobile_pipeline.py`, `mobile_context.py` | Needs new v2 equivalent in Phase D | Phase D |
