# `src/vxis/` — Core Library Module Index

> 33 submodules. Each has its own `README.md`. This file is the map.

## Phase A core (modules actively used by the Strix-parity loop)

| Module | Role | Key files |
|---|---|---|
| [`agent/`](agent/README.md) | **Brain + single loop + tools** — the heart of Phase A | `brain.py`, `scan_loop.py`, `tool_registry.py`, `tools/` |
| [`agent/tools/`](agent/tools/README.md) | 11 BrainTool implementations — control, primitive, Strix-power, finding CRUD | `control_tools.py`, `shell_tools.py`, `python_tools.py`, `finding_tools.py`, `hands_tools.py` |
| [`pipeline/`](pipeline/README.md) | Scan orchestration entrypoint (v1 legacy 5234 lines, v2 thin shim 360 lines) | `scan_pipeline_v2.py`, `pipeline.py` (deprecated), `context.py` |
| [`interaction/`](interaction/README.md) | Hands / Eyes / X-Ray primitives — HTTP client, headless browser, MitM proxy | `hands.py`, `eyes.py`, `xray.py`, `controller.py` |
| [`cli/`](cli/README.md) | `vxis` command-line entrypoint (Typer + Rich TUI) | `main.py`, `interactive.py`, `live_display.py` |
| [`llm/`](llm/README.md) | LLM client + fallback router | `client.py`, `router.py` |
| [`report/`](report/README.md) | NCC-style HTML report generator | `generator.py` |
| [`evidence/`](evidence/README.md) | Evidence schema re-exports | `schema.py` |
| [`models/`](models/README.md) | Pydantic data models (Finding, CVSS, Severity, Reference, MITRE ATT&CK) | `finding.py` |

## Phase A legacy (to be removed in Task 12)

| Module | Status |
|---|---|
| [`phases/`](phases/README.md) | **DEPRECATED** — PhaseGuide metadata for the old 14-phase pipeline; slated for deletion |

## Recon / intelligence layer

| Module | Role |
|---|---|
| [`mission/`](mission/README.md) | Scan mission config (scope, depth, perspective) |
| [`scope/`](scope/README.md) | Scope enforcement — URL pattern allow/deny |
| [`knowledge/`](knowledge/README.md) | Vulnerability knowledge base (compiled patterns, KB store) |
| [`biometrics/`](biometrics/README.md) | Phase 13 (legacy): behavioral biometrics via GitHub/LinkedIn OSINT |
| [`twin/`](twin/README.md) | Phase 15 (legacy): Digital Twin pre-simulation |
| [`forecast/`](forecast/README.md) | Phase 14 (legacy): temporal vulnerability forecasting |
| [`industry/`](industry/README.md) | Industry-wide autonomous scan coordinator |

## Execution / exploitation layer

| Module | Role |
|---|---|
| [`primitives/`](primitives/README.md) | Pure tool functions with zero LLM calls (crawl, fingerprint, sensing, etc.) |
| [`mutation/`](mutation/README.md) | Phase 11 (legacy): attack chain mutation engine |
| [`synthesis/`](synthesis/README.md) | Cross-protocol attack chain synthesis |
| [`graph/`](graph/README.md) | Living attack graph + hypothesis queue |
| [`ghost/`](ghost/README.md) | Stealth / anti-attribution layer (proxy rotation, UA spoofing, timing jitter) |
| [`plugins/`](plugins/README.md) | Plugin system for external scanner integrations |

## Intelligence / scoring / learning

| Module | Role |
|---|---|
| [`scoring/`](scoring/README.md) | Capability scoring system (VXIS score calculator) |
| [`evolution/`](evolution/README.md) | Phase 12 (legacy): self-evolving agent synthesis |
| [`growth/`](growth/README.md) | Growth Layer — self-growth intelligence bootstrap |

## Infrastructure / ops

| Module | Role |
|---|---|
| [`config/`](config/README.md) | Configuration loading + validation |
| [`core/`](core/README.md) | Cross-cutting utilities |
| [`data/`](data/README.md) | Data directory helpers |
| [`display/`](display/README.md) | Rich TUI live display (CRT-style output) |
| [`dashboard/`](dashboard/README.md) | Web dashboard backend |
| [`scheduler/`](scheduler/README.md) | Continuous monitoring scheduler |
| [`watchers/`](watchers/README.md) | 24/7 real-time threat watcher daemons |
| [`integrations/`](integrations/README.md) | External webhook integrations |

## Top-level files

| File | Purpose |
|---|---|
| `mcp_server.py` | MCP (Model Context Protocol) server — exposes VXIS as an MCP tool for Claude Code |
| `registry.py` | Plugin / module registry bootstrap |
