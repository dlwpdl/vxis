# `src/vxis/agent/tools/` — 11 BrainTool Implementations

> The tools the Brain can call during a scan. `build_default_registry()` registers all 11 into a `ToolRegistry` that `ScanAgentLoop` passes to `think_in_loop` as the tool catalog.

## Registration entry point

```python
from vxis.agent.tools import build_default_registry
reg = build_default_registry()
# → 11 tools registered
```

## Tool catalog (11 tools, grouped by layer)

### Control tools (`control_tools.py` — Task 5)

Tools the Brain uses to manage the loop itself. Minimal wrappers, no external dependencies.

| Tool | What it does |
|---|---|
| `finish_scan` | Signal end of scan. Required input: none. ScanAgentLoop stops when this returns `ok=True`. |
| `think` | Scratchpad. Logs a reasoning step. No side effects. Input: `thought: string`. |
| `wait` | Brief pause (max 5s, clamped). Input: `seconds: number`. Useful for rate-limit backoff. |

### Primitive tools (`hands_tools.py` — Task 6)

Thin wrappers over the `vxis.interaction` primitives. Module-level singletons preserve state across tool calls within a scan.

| Tool | Wraps | Notes |
|---|---|---|
| `http_request` | `SessionManager.get_session().request()` (`interaction/hands.py`) | Singleton session manager → auth cookies / CSRF tokens persist across calls. Returns parsed `AnalyzedResponse` (status, body, links, forms). |
| `browser_render` | `BrowserEngine + BrowserPage.navigate() + snapshot()` (`interaction/eyes.py`) | One-shot lifecycle per call (start → new_page → navigate → snapshot → stop). Graceful fail if Playwright is not installed. |
| `intercept_proxy` | `MitmProxy + FlowAnalyzer` (`interaction/xray.py`) | Action-based: `start` / `stop` / `flows`. Graceful fail if mitmproxy not installed. |

### Strix-power tools (`shell_tools.py` + `python_tools.py` — Tasks 7–8)

The two tools that give the Brain **real hacker power**. Both run inside the shared `vxis-sandbox` Docker container (`docker/sandbox/Dockerfile`). Lifecycle managed by `_ensure_sandbox_running()` in `shell_tools.py` — container is lazy-started on first call and reused warm across scans (Strix convention).

| Tool | What it does |
|---|---|
| `shell_exec` | **Unrestricted shell** inside `vxis-sandbox`. Input: `command: string`, optional `timeout: number (default 120, max 600)`. Returns `{exit_code, stdout, stderr}`. Use for sqlmap / nuclei / ffuf / gobuster / dirb / curl. **No command whitelist.** |
| `python_exec` | **Multi-line Python 3** inside the same sandbox. Input: `code: string`, optional `timeout`. Writes code to `/workspace/_python_exec_<uuid>.py` (bind-mounted at `/tmp/vxis-workspace` on host), dispatches `docker exec vxis-sandbox python3 <path>`, cleans up on both success and error paths. Use for asyncio/aiohttp payload sprays, custom PoC scripts, post-exploitation automation. |

**Security note**: `shell_exec` bypasses the Hands-layer deferred mutation queue because sqlmap / nuclei make their own HTTP requests. For Phase A (local Docker targets) this is intentional — "real hacker simulation". Phase C will add a second-layer egress filter on the sandbox for enterprise scans against customer production.

**Shared workspace**: `/tmp/vxis-workspace` on host ↔ `/workspace` inside container. Files written by `shell_exec` are visible to `python_exec` and vice versa. State persists across tool calls within a scan.

### Finding CRUD (`finding_tools.py` — Task 9)

Module-level in-memory store for Phase A. Phase B may swap for a persistent episodic memory DB.

| Tool | What it does |
|---|---|
| `report_finding` | Brain submits a discovered vulnerability. Required: `title`, `severity` (critical/high/medium/low/informational), `finding_type` (snake_case), `affected_component`, `description`. Optional: `evidence`, `remediation`, `cwe`. Auto-assigns `VXIS-0001`, `VXIS-0002`, … IDs. |
| `query_findings` | Search the current scan's findings. Filters: `severity`, `finding_type`, `component_contains`, `text_contains` (matches title + description). Default limit 20. |
| `link_chain` | Assert a causal attack chain between ≥2 previously-reported findings. Required: `finding_ids: list[str]` (≥2), `rationale: string`. Optional: `crown_jewel: string`. Rejects unknown IDs. |

**Accessors for integration** (used by `ScanPipelineV2`):

```python
from vxis.agent.tools.finding_tools import _get_findings, _get_chains, _reset_for_tests
_reset_for_tests()          # Clear between scans
findings = _get_findings()  # list[dict] — copy into ctx.findings as Finding objects
chains = _get_chains()      # list[dict] — copy into ctx.attack_chains
```

## Forward-compatibility convention

Several `build_default_registry_*` tests use `assert len(names) >= N` instead of `== N` so adding tools in future tasks doesn't break existing tests. This pattern was established in commits `3f3b908` and the corresponding fix in `402ba14`.

## Adding a new tool

1. Create the tool class implementing the `BrainTool` protocol (`name`, `description`, `input_schema`, `async run(**kwargs) -> ToolResult`).
2. Add it to `__init__.py` imports + `__all__` + `build_default_registry()`.
3. Write tests in `tests/agent/tools/test_<new>_tools.py` — at minimum: protocol conformance, happy path, one failure mode, registry integration.
4. If the tool manages state, include a `_reset_for_tests()` module-level helper.
5. Update this README's tool table.
