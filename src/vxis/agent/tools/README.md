# `src/vxis/agent/tools/` — 25 BrainTool Implementations

> The tools the Brain can call during a scan. `build_default_registry()` registers all 25 into a `ToolRegistry` that `ScanAgentLoop` passes to `think_in_loop` as the tool catalog.

## Registration entry point

```python
from vxis.agent.tools import build_default_registry
reg = build_default_registry(brain=agent_brain)
# -> 25 tools registered
```

## Tool catalog (25 tools, grouped by layer)

### Control tools (`control_tools.py`) — 3 tools

Tools the Brain uses to manage the loop itself.

| Tool | What it does |
|---|---|
| `finish_scan` | Signal end of scan. ScanAgentLoop stops when this returns `ok=True`. |
| `think` | Scratchpad. Logs a reasoning step. No side effects. Input: `thought: string`. Think-first pattern: Brain should call this when uncertain. |
| `wait` | Brief pause (max 5s, clamped). Input: `seconds: number`. Useful for rate-limit backoff. |

### Agent graph tool (`agent_graph_tools.py`) — 1 tool

| Tool | What it does |
|---|---|
| `agent_graph` | Records delegated scan tasks, worker roles, messages, statuses, bounded child-turn executions, and final results. Child turns run only when ScanAgentLoop installs an executor, and delegated tasks still require explicit `finish` with a concrete result. |

### Fingerprint tool (`fingerprint_tools.py`) — 1 tool

| Tool | What it does |
|---|---|
| `fingerprint_target` | Detect target technology stack (framework, language, server, security features). Returns structured fingerprint with stack hints for playbook selection. |

### Browser tools (`browser_tools.py`) — 7 tools

Phase C/D Eyes integration. Playwright-backed headless browser for rendered-page visibility. All tools gracefully fail if Playwright is not installed.

| Tool | What it does |
|---|---|
| `browser_navigate` | Navigate to a URL, return page title + status. |
| `browser_analyze_dom` | Deep DOM analysis: forms, links, scripts, hidden fields, meta tags. |
| `browser_click` | Click an element by CSS selector. |
| `browser_fill_form` | Fill and submit a form (selector + field values). |
| `browser_screenshot` | Take a PNG screenshot of the current page. |
| `browser_eval_js` | Execute arbitrary JavaScript in the page context. Returns result. |
| `browser_get_cookies` | Get all cookies for the current page. |

### Legacy browser tool (`hands_tools.py`) — 1 tool

| Tool | What it does |
|---|---|
| `browser_render` | Legacy Phase A one-shot browser render (navigate → snapshot → stop). Kept for backward compatibility. Prefer the browser_* tools above. |

### HTTP + Proxy tools (`hands_tools.py`) — 2 tools

Thin wrappers over `vxis.interaction` primitives. Module-level singletons preserve auth state across calls.

| Tool | Wraps | Notes |
|---|---|---|
| `http_request` | `SessionManager.get_session().request()` | Singleton session manager → auth cookies / CSRF tokens persist. Returns `AnalyzedResponse` (status, body, links, forms). |
| `intercept_proxy` | `MitmProxy + FlowAnalyzer` | Action-based: `start` / `stop` / `flows`. Graceful fail if mitmproxy not installed. |

### Strix-power tools (`shell_tools.py` + `python_tools.py`) — 2 tools

Both run inside the shared `vxis-sandbox` Docker container. Lifecycle: lazy-started on first call, reused warm across scans.

| Tool | What it does |
|---|---|
| `shell_exec` | **Unrestricted shell** inside `vxis-sandbox`. Input: `command`, optional `timeout` (default 120, max 600). Returns `{exit_code, stdout, stderr}`. Use for sqlmap / nuclei / ffuf / gobuster / nmap / curl. **No command whitelist.** |
| `python_exec` | **Multi-line Python 3** inside the same sandbox. Input: `code`, optional `timeout`. For custom PoC scripts, payload sprays, post-exploitation automation. |

**Security**: `shell_exec` bypasses the Hands-layer deferred mutation queue. Enterprise egress filter (`VXIS_EGRESS_STRICT=1`) constrains sandbox outbound traffic.

**Shared workspace**: `/tmp/vxis-workspace` (host) ↔ `/workspace` (container).

### Playbook tools (`playbook_tools.py`) — 2 tools

| Tool | What it does |
|---|---|
| `list_playbooks` | List all available playbook names (injection_vectors, auth_bypass, xss, etc.). |
| `load_playbook` | Load a specific playbook by name. Returns stack-specific attack techniques and patterns. |

### Finding CRUD (`finding_tools.py`) — 3 tools

In-memory store per scan. Auto-assigns `VXIS-0001`, `VXIS-0002`, ... IDs.

| Tool | What it does |
|---|---|
| `report_finding` | Submit a discovered vulnerability. Required: `title`, `severity`, `finding_type`, `affected_component`, `description`. Optional: `evidence`, `remediation`, `cwe`. |
| `query_findings` | Search current scan's findings. Filters: `severity`, `finding_type`, `component_contains`, `text_contains`. |
| `link_chain` | Assert causal attack chain between 2+ findings. Required: `finding_ids: list[str]`, `rationale`. High-value chains also require `evidence_artifact` with source output reuse, control/observed result, and crown evidence. |

### Verifier tool (`verifier_tools.py`) — 1 tool

| Tool | What it does |
|---|---|
| `verify_finding` | **Adversarial verifier.** Uses a stronger model to attempt to refute a claimed finding. Input: finding details + evidence. Returns verdict: `CONFIRMED` / `UNCONFIRMED` / `REFUTED` with reasoning. Injected with `brain` instance for provider fallback chain reuse. |

### Memory tool (`memory_tools.py`) — 1 tool

| Tool | What it does |
|---|---|
| `query_scan_memory` | Query the cross-scan episodic memory KB. Returns relevant past findings, techniques, and failed attempts from similar targets. |

### Skill runner (`skill_runner.py`) — 1 tool

| Tool | What it does |
|---|---|
| `run_skill` | Execute a curated VXIS skill with structured arguments and loop-guarding. Used for focused recon/exploit/post-auth workflows. |

### MITRE data (`mitre_data.py`) — not a tool, support module

16 web-focused MITRE ATT&CK techniques. `infer_techniques(finding_type, title, affected_component)` returns matching technique IDs. `compute_mitre_coverage(findings)` returns coverage summary for the report.

## Adding a new tool

1. Create the tool class implementing the `BrainTool` protocol (`name`, `description`, `input_schema`, `async run(**kwargs) -> ToolResult`).
2. Add it to `__init__.py` imports + `__all__` + `build_default_registry()`.
3. Add its target-facing egress contract to `vxis.agent.egress_contract.TOOL_TARGET_EGRESS`.
4. Write tests in `tests/agent/tools/test_<new>_tools.py` — at minimum: protocol conformance, happy path, one failure mode, registry integration.
5. If the tool manages state, include a `_reset_for_tests()` module-level helper.
6. Update this README's tool table.

## Forward-compatibility convention

Several tests use `assert len(names) >= N` instead of `== N` so adding tools doesn't break existing tests.
