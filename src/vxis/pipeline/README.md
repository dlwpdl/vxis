# `src/vxis/pipeline/` — Scan Orchestration Entry Point

> The top of the scan stack. CLI instantiates a `ScanPipeline` and calls `run(target)`. The live implementation is `scan_pipeline_v2.py`, whose job is to launch the worker loop and preserve the AI review hierarchy around it.

## Files

| File | Role | Status |
|---|---|---|
| **`scan_pipeline_v2.py`** (~505 lines) | **LIVE** — thin shim. Builds `ScanContext`, resets counters, creates `ScanAgentLoop` + `ToolRegistry`, runs the loop, copies findings/chains, extracts final report sections, generates HTML report (with verification summary + MITRE coverage), computes VXIS score, emits `VXIS_BENCHMARK` line. | Live (CLI imports from here) |
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
     - branch persistence / vector exhaustion
     - PoC-gated auto-promotion
     - adversarial verification
     - Auto-orchestration safety net
     - Scan dashboard injection every iteration
     - Enterprise egress filter (if VXIS_EGRESS_STRICT=1)
  9. Copy _get_findings() → ctx.findings (with Finding object conversion)
 10. Copy _get_chains() → ctx.attack_chains
 11. Extract final `executive_summary/methodology/technical_analysis/recommendations`
 12. Compute MITRE ATT&CK coverage → ctx
 13. If ctx.deferred_actions: await _run_deferred_gate(ctx)  # enterprise
 14. await _generate_report(ctx)  # NCC-style HTML + verification summary + MITRE table
 15. ctx.vxis_score = _SimpleScore(total=..., grade=...)
 16. Print: VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> ...
 17. Return ctx
```

## Architectural role

`ScanPipelineV2` is intentionally thin. It should not become a second strategist.

Its job is:

- launch the worker runtime,
- preserve the verifier/judge outputs,
- turn accepted findings into exportable artifacts,
- enforce top-level scan bookkeeping.

It should not:

- reintroduce phase dispatch,
- micromanage vector priorities,
- override loop-level review decisions.

## What the v2 shim does NOT do (vs legacy v1)

- No per-phase dispatch — Brain decides dynamically
- No profile-hardcoded attempt counts
- No `_consult_brain_for_phase_vectors` — Brain reads its own context via messages
- No `_build_batch_brain_decisions` — Brain gets tool catalog, not pre-chosen vectors
- No human review checkpoint as a mandatory stage — review is handled primarily by AI gates inside the loop

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
