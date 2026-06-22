# `src/vxis/` — Core Library Module Index

> Production-importable modules. Each linked module has its own `README.md`.
> This file is the map.

## Core Runtime

| Module | Role | Key files |
|---|---|---|
| [`agent/`](agent/README.md) | **Brain + single loop + tools** — the active scan runtime | `brain.py`, `scan_loop.py`, `tool_registry.py`, `tools/` |
| [`agent/tools/`](agent/tools/README.md) | 11 BrainTool implementations — control, primitive, Strix-power, finding CRUD | `control_tools.py`, `shell_tools.py`, `python_tools.py`, `finding_tools.py`, `hands_tools.py` |
| [`pipeline/`](pipeline/README.md) | Scan orchestration entrypoint over the Brain-first loop | `scan_pipeline_v2.py`, `context.py` |
| [`interaction/`](interaction/README.md) | Hands / Eyes / X-Ray primitives — HTTP client, headless browser, MitM proxy | `hands.py`, `eyes.py`, `xray.py`, `controller.py` |
| [`cli/`](cli/README.md) | `vxis` command-line entrypoint (Typer + Textual tree TUI, Rich fallback) | `main.py`, `scan_tui.py`, `scan_display.py` |
| [`llm/`](llm/README.md) | LLM client + fallback router | `client.py`, `router.py` |
| [`report/`](report/README.md) | NCC-style HTML report generator | `generator.py` |
| [`evidence/`](evidence/README.md) | Evidence schema re-exports | `schema.py` |
| [`models/`](models/README.md) | Pydantic data models (Finding, CVSS, Severity, Reference, MITRE ATT&CK) | `finding.py` |

## Recon / intelligence layer

| Module | Role |
|---|---|
| [`mission/`](mission/README.md) | Scan mission config (scope, depth, perspective) |
| [`scope/`](scope/README.md) | Scope enforcement — URL pattern allow/deny |
| [`knowledge/`](knowledge/README.md) | Vulnerability knowledge base (compiled patterns, KB store) |
| [`industry/`](industry/README.md) | Industry-wide autonomous scan coordinator |

## Execution / exploitation layer

| Module | Role |
|---|---|
| [`primitives/`](primitives/README.md) | Pure tool functions with zero LLM calls (crawl, fingerprint, sensing, etc.) |
| [`synthesis/`](synthesis/README.md) | Cross-protocol attack chain synthesis |
| [`ghost/`](ghost/README.md) | Stealth / anti-attribution layer (proxy rotation, UA spoofing, timing jitter) |
| [`plugins/`](plugins/README.md) | Plugin system for external scanner integrations |

## Intelligence / scoring / learning

| Module | Role |
|---|---|
| [`scoring/`](scoring/README.md) | Capability scoring system (VXIS score calculator) |
| [`growth/`](growth/README.md) | Growth Layer — self-growth intelligence bootstrap |

## Infrastructure / ops

| Module | Role |
|---|---|
| [`config/`](config/README.md) | Configuration loading + validation |
| [`core/`](core/README.md) | Cross-cutting utilities |
| [`data/`](data/README.md) | Data directory helpers |
| [`dashboard/`](dashboard/README.md) | Web dashboard backend |
| [`scheduler/`](scheduler/README.md) | Continuous monitoring scheduler |
| [`watchers/`](watchers/README.md) | 24/7 real-time threat watcher daemons |
| [`integrations/`](integrations/README.md) | External webhook integrations |

## Top-level files

| File | Purpose |
|---|---|
| `mcp_server.py` | MCP (Model Context Protocol) server — exposes VXIS as an MCP tool for Claude Code |
| `registry.py` | Plugin / module registry bootstrap |
