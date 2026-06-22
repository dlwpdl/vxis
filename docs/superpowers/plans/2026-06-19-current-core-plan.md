# VXIS Current Core Plan - 2026-06-19

## Goal

Keep VXIS as a lean autonomous testing app: target in, one Brain-controlled
runtime loop, verified findings out. Prioritize fast context, real execution,
and low false-positive rate over broad but disconnected feature listings.

## Live Architecture

- Runtime entrypoint: `ScanPipelineV2`
- Loop owner: `ScanAgentLoop`
- Brain path: `AgentBrain.think_in_loop()`
- Tools: `ToolRegistry` with BrainTools only
- Findings: per-scan `FindingStore`, `report_finding`, `verify_finding`,
  `link_chain`
- UI: Textual tree TUI as canonical CLI surface, Rich fallback only
- MCP: working primitive and scan tools only; no deleted phase wrappers
- Context: 200k cloud segments by default, concise bullet compression, pinned
  findings/evidence/failures/credentials
- Development boundary: incomplete feature work lives under top-level
  `incubator/` until it is complete, tested, and intentionally moved into
  `src/vxis`.

## Strix Comparison

- Same direction: single persistent ReAct loop, one tool per turn, compact
  state, branch pressure, concrete tool evidence.
- VXIS difference: stronger verifier and report contract, stricter scope/policy
  gates, optional dashboard/MCP surfaces.
- Avoid: resurrecting specialist-agent fleets, phase registries, placeholder
  routes, stale cache reliance, or docs that describe features not wired into
  runtime.

## Immediate Priorities

1. Keep production imports clean.
2. Reduce the largest scan-loop mixins without changing behavior.
3. Consolidate duplicate CLI display paths.
4. CODE/static helpers stay library/test-only; live Brain scans remain black-box
   until source-aware tools are finished and promoted from `incubator/`.
5. Add small regression tests whenever a public surface is wired.

## Non-Goals

- No new phase registry.
- No placeholder MCP/CLI/dashboard links.
- No WIP feature code in `src/vxis` unless it is intentionally production
  importable.
- No public white/grey-box claim until source-aware Brain tools exist and are
  exercised through the live scan loop.
- No empty/import-only tests or tests that preserve placeholder stubs as if they
  were product behavior.
- No large context accumulation just because the model supports it.

## Success Gates

- `uv run ruff check src/vxis tests`
- `uv run pytest -q`
- no imports of deleted modules
- no tracked runtime artifacts such as reports, caches, `.DS_Store`, WAL/SHM, or
  pycache files
- docs point to this plan plus `docs/superpowers/DECISIONS.md` as the current
  source of truth
