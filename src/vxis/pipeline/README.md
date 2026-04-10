# `src/vxis/pipeline/` — Scan Orchestration Entry Point

> The top of the scan stack. CLI instantiates a `ScanPipeline` and calls `run(target)`. The live implementation is `scan_pipeline_v2.py`.

## Files

| File | Role | Status |
|---|---|---|
| **`scan_pipeline_v2.py`** (~505 lines) | **LIVE** — thin shim. Builds `ScanContext`, resets counters, creates `ScanAgentLoop` + `ToolRegistry` (23 tools), runs the loop, copies findings/chains, generates HTML report (with verification summary + MITRE coverage), computes VXIS score, emits `VXIS_BENCHMARK` line. | Live (CLI imports from here) |
| **`pipeline.py`** (5234 lines) | **DEPRECATED** — legacy 14-phase `ScanPipeline`. Violates Brain-First principle. | Dead code |
| `context.py` | `ScanContext` dataclass — per-scan state container (target, scan_id, findings, attack_chains, vxis_score, duration, deferred_actions, etc.). | Live |
| `game_pipeline.py` / `game_context.py` | Game-target pipeline variant (legacy) | Legacy |
| `mobile_pipeline.py` / `mobile_context.py` | Mobile-target pipeline variant (legacy) | Legacy |

## CLI → pipeline entry

```python
from vxis.pipeline.scan_pipeline_v2 import ScanPipeline
```

## ScanPipelineV2 flow

```
ScanPipeline.run(target, app_context_en="", app_context_ko="", resume_from=None)
  1. Build ScanContext(target, scan_id, ...)
  2. Activate ghost (if brain_mode=uncensored or ghost:// trigger)
  3. reset_finding_store()
  4. reset_brain_decision_count()
  5. reset_llm_call_count()
  6. registry = build_default_registry(brain=brain)  # 23 BrainTools
  7. loop = ScanAgentLoop(target, registry, brain, max_iters=300)
  8. loop_result = await loop.run()       # ReAct loop with:
     - 1 tool per message (Strix pattern)
     - LLM memory compression at 90K tokens
     - 3-tier smart history
     - Auto-orchestration safety net
     - Scan dashboard injection every iteration
     - Enterprise egress filter (if VXIS_EGRESS_STRICT=1)
  9. Copy _get_findings() → ctx.findings (with Finding object conversion)
 10. Copy _get_chains() → ctx.attack_chains
 11. Compute MITRE ATT&CK coverage → ctx
 12. If ctx.deferred_actions: await _run_deferred_gate(ctx)  # enterprise
 13. await _generate_report(ctx)  # NCC-style HTML + verification summary + MITRE table
 14. ctx.vxis_score = _SimpleScore(total=..., grade=...)
 15. Print: VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> ...
 16. Return ctx
```

## What the v2 shim does NOT do (vs legacy v1)

- No per-phase dispatch — Brain decides dynamically
- No profile-hardcoded attempt counts
- No `_consult_brain_for_phase_vectors` — Brain reads its own context via messages
- No `_build_batch_brain_decisions` — Brain gets tool catalog, not pre-chosen vectors

## Finding dict → Finding object conversion

`_finding_dict_to_finding_object()` converts the in-memory `finding_tools` store dicts into `Finding` Pydantic objects with:
- Severity: string → `Severity.CRITICAL / HIGH / MEDIUM / LOW / INFO`
- Title / description / remediation: bilingual `"EN|||EN"`
- Evidence: `list[Evidence]`
- CVSS: severity-weighted generic vector via `CVSSVector`
- CWE: only if explicitly provided
- MITRE ATT&CK: auto-inferred from `finding_type` via `mitre_data.infer_techniques()`
- Verification verdict: from adversarial verifier results

## Critical rules

- **Do NOT modify `scan_pipeline_v2.py` to emit per-phase events** — defeats Brain-First principle.
- **Do NOT restore `_consult_brain_for_vector` or `_execute_brain_decisions`** from pipeline.py.
- **Deferred mutation gate preserved** but currently bypassed by shell_exec. Enterprise egress filter at sandbox layer covers this.
- **Report generation wrapped in try/except** — broken report doesn't break the scan.

## Deprecation schedule

| File | Status | Removal |
|---|---|---|
| `pipeline.py` | Dead code (no live imports) | Pending cleanup |
| `game_pipeline.py`, `game_context.py` | Needs v2 equivalent | Future domain expansion |
| `mobile_pipeline.py`, `mobile_context.py` | Needs v2 equivalent | Future domain expansion |
