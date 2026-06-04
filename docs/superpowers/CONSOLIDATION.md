# VXIS v3 Phase 0 Consolidation Ledger

This ledger tracks the systems being collapsed during v3.2 Phase 0. Deletion is deferred unless rollback remains safe.

| Old symbol/path | New home | Consumers re-pointed | Removal commit | Grep guard |
|---|---|---|---|---|
| `AgentMemory` / `ScanMemory` (`src/vxis/agent/memory.py`) | PTI dossier via `src/vxis/pti/memory_bridge.py` | `core/orchestrator.py` dual-writes through `dual_write_scan`; `brain.py` reads PTI when `VXIS_V3_MEMORY=1` | Deferred to Phase 2 after parity | `rg "AgentMemory|remember_scan|recall_similar" src/vxis` |
| `query_scan_memory` JSON KB (`src/vxis/agent/tools/memory_tools.py`) | PTI-backed `query_scan_memory_view` behind `VXIS_V3_MEMORY` | `QueryScanMemoryTool.run` keeps the same tool name and data contract | Deferred to Phase 2 after parity | `rg "_load_kb|record_scan_result|migrate_scan_kb" src/vxis/agent/tools/memory_tools.py` |
| DAG `Hypothesis` class (`src/vxis/agent/hypothesis/dag.py`) | `HypothesisNode` | `hypothesis_tools`, `scan_loop_v3`, and tests updated | Completed in Phase 0 | `rg "^class Hypothesis\\b" src/vxis` should only show `src/vxis/graph/hypothesis.py` |
| `cost_router.ROUTE_TABLE` and route env overrides | `AgentBrain._model_role_for_decision_class` + `hybrid_config` | `BrainCostRouter` now emits `CostReport` telemetry only; `scan_loop_v3` reads model ref from Brain config | Completed in Phase 0 | `rg "ROUTE_TABLE|ROUTE_OVERRIDE_ENV_PREFIX|ROUTE_TABLE_ENV|model_for\\(" src/vxis` |
| `vector_candidates` finish priority | `HypothesisDAG.top_untested()` / `dag_blocks_finish()` | `ensure_vector_candidate` seeds `HypothesisNode`; candidate outcomes update node status | Legacy side-table deletion deferred | `rg "_blocking_finish_branches|_remaining_high_yield_family_candidates" src/vxis` |
| `scan_todos` priority | Projection from candidate/DAG state | UI snapshot still reads side-table during parity | Deferred | Field map: `docs/superpowers/plans/phase0-prioritizer-mapping.md` |
| `branches` finish priority | DAG blocker ids with branch side-table projection | Finish rejection and dashboard use `_dag_finish_blocking_branches` | Deferred | `rg "_dag_finish_blocking_branches|dag_blocks_finish" src/vxis/agent` |
| Live benchmark on PR | Deterministic PR tier + live scheduled/manual tier | `.github/workflows/benchmark.yml` PR job runs `pytest -m "not live"` without API keys/services | Completed in Phase 0 | `grep -n "pull_request\\|schedule\\|ANTHROPIC_API_KEY\\|-m \\\"not live\\\"" .github/workflows/benchmark.yml` |

## Rollback Notes

`VXIS_V3_MEMORY=off` keeps the legacy `AgentMemory` and JSON KB paths live. The PTI shadow path is additive in Phase 0, so rollback does not require data migration.

## Deferred Deletions

Do not delete `AgentMemory`, the JSON KB helpers, `VectorCandidate`, `ScanTodo`, or `BranchState` in Phase 0. They are still compatibility projections until parity is measured in a later phase.
