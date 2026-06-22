# VXIS Slop Cleanup Audit - 2026-06-19

## Cleaned in this pass

- Removed broken MCP `phase_*` tool exposure. The advertised tools imported `vxis.phases`, which no longer exists, so production tool discovery could list calls that failed at runtime.
- Fixed MCP `scope_check_url` and `scope_check_action` execution. The handlers now match the current `load_scope(...).check_*` API and have regression coverage that performs real `tools/call` requests.
- Added optional dependency guards for CLI commands that require `docx` or `fastapi`. Default installs now fail with an actionable install hint instead of `ModuleNotFoundError`.
- Removed tracked generated/runtime artifacts: `.DS_Store`, SQLite WAL/SHM files, root `report_*.html`, `.vxis/cache/extractions/*`, `.vxis/signals/processed/*`, and `.vxis/signals/test-pending/*`.
- Tightened `.gitignore` so the same generated artifacts do not come back.
- Removed unused imports that made `ruff check src/vxis tests` fail.
- Moved finding/chains/event-callback state behind a per-scan `FindingStore`
  bound by context variable during `ScanPipeline.run()`.
- Moved `run_skill` stuck-loop cache and skills-ever-called tracking from
  module globals to each `RunSkillTool` instance, so a later scan of the same
  target starts fresh.
- Made the Textual tree TUI the canonical terminal UI path and stopped the CLI
  fallback display from initializing the old `WEB_PHASES` registry.
- Added cloud context segmentation at 200k tokens by default and changed
  compression summaries to terse AI-readable bullets.
- Removed dead legacy/prototype modules that were not imported by live code,
  tests, package entrypoints, or workflows: unused agent runner/protocol helpers,
  WAF/business/threat/report stubs, obsolete synthesis PoC/honeypot/defense
  prototypes, duplicate dashboard route files, and orphan mobile agent files.
- Moved the dashboard knowledge-base routes into the live dashboard app so the
  existing `/kb` sidebar link resolves without depending on an unregistered
  route module.
- Added wheel package-data coverage for runtime HTML/CSS/Markdown assets so
  dashboard pages, report templates, and agent playbooks survive packaging.
- Removed the old `BaseAgent` / `DirectorAgent` phase pipeline, 63-agent fleet,
  legacy `AgentExecutor`, attack graph, hypothesis queue, CRT display, and the
  `auto_pentest.py` script that depended on them. These were not connected to
  the live `ScanPipelineV2` runtime and were kept alive only by legacy tests.
- Fixed manifest multi-scan Brain construction so it uses the current
  `AgentBrain()` constructor instead of the deleted `config=` signature.

## Remaining high-priority cleanup targets

1. `src/vxis/agent/scan_loop_decision_policy.py:46` - `_dag_finish_blocking_branches()` is named and used like a query, but mutates branch status at lines 52, 66, and 73. Split this into an explicit mutation step plus a pure blocker query before changing finish-gate behavior.

2. Giant scan-loop surfaces still need decomposition:
   - `src/vxis/agent/scan_loop_decision_policy.py:45` - `ScanLoopDecisionPolicyMixin`, 2782 lines.
   - `src/vxis/agent/scan_loop_actions.py:21` - `ScanLoopActionMixin`, 2172 lines.
   - `src/vxis/agent/scan_loop_agent_graph.py:58` - `ScanLoopAgentGraphMixin`, 1753 lines.
   - `src/vxis/agent/scan_loop_run.py:27` - `run()`, 1510 lines.
   - `src/vxis/cli/main.py:194` - `scan()`, 766 lines.

3. Resolved 2026-06-19: CLI live display is no longer split across two
   modules. `src/vxis/cli/live_display.py` was deleted, and the legacy
   `ScanSnapshot` renderer now lives in `src/vxis/cli/scan_display.py` as
   `SnapshotLiveDisplay`.

## Rule for future wiring

Do not expose placeholder, empty, deleted, or non-working features through CLI, MCP, dashboard, or runtime registries. Wire features into public production entrypoints only after the implementation works and has an execution test, not just a listing or registration test.

Incomplete feature work should live outside `src/` in an incubator/labs area
with its own README/status and local tests. Promote it into `src/vxis/...` only
when it is ready to be imported, packaged, and intentionally wired into a public
runtime surface.
