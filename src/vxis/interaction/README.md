# `src/vxis/interaction/` — Hands / Eyes / X-Ray Primitives

> The physical execution layer. Raw HTTP, headless browser, MitM proxy — wrapped by Phase A's BrainTool adapters in `agent/tools/hands_tools.py`.

## Four primitives

| File | Class | Role | BrainTool wrapper |
|---|---|---|---|
| `hands.py` | `SessionManager` + `TargetSession` + `RequestChain` + `_analyze_response` | HTTP client with session pooling, auth state tracking, CSRF auto-injection, response analysis (forms/links/WAF detection), adaptive timeout. | `HttpRequestTool` (`http_request`) |
| `eyes.py` | `BrowserEngine` + `BrowserPage` + `DOMAnalysis` + `PageSnapshot` | Playwright-backed headless browser. DOM snapshot, JS execution, form fill, screenshot. | `BrowserRenderTool` (`browser_render`) |
| `xray.py` | `FlowAnalyzer` + `MitmProxy` + `CapturedFlow` + `InterceptRule` | MitM HTTP proxy for passive traffic capture + active response rewriting. Auth flow / API flow / vulnerability pattern detection. | `InterceptProxyTool` (`intercept_proxy`) |
| `controller.py` | `InteractionController` | Intent-based auto-selector — picks the right primitive for a given intent. Legacy: used by old pipeline.py. | (none; v2 uses primitives directly via BrainTools) |

## Phase A integration

`agent/tools/hands_tools.py` wraps these primitives with:
- **Module-level singletons** for `SessionManager` so auth cookies / CSRF tokens persist across Brain tool calls within a scan (improvement over legacy `pipeline.py` which instantiated a fresh `SessionManager` per phase, losing auth state)
- **One-shot lifecycle** for `BrowserEngine` (start → new_page → navigate → snapshot → stop per call — wasteful but simple; Phase B may pool)
- **Action-based dispatch** for `MitmProxy` (`start` / `stop` / `flows`) with graceful fail on missing mitmproxy dependency

## Key behaviors worth knowing

**Hands adaptive timeout** (`hands.py:505-515`): after 2 consecutive httpx.TimeoutException events, the session's effective timeout multiplies by 1.5x up to a cap of `base_timeout * 1.5`. This prevents a single slow endpoint (e.g. blind time-based SQLi) from paralyzing the whole scan. Fix was applied in commit `106e7d2`.

**Hands CSRF auto-injection** (`hands.py:499-503`): POST/PUT/PATCH/DELETE requests automatically get CSRF tokens injected into headers and form data. Tokens are harvested from form fields, response headers, and cookies.

**Hands WAF detection** (`hands.py:556-558`): when `analyzed.is_waf_block` or `analyzed.is_rate_limited` is true, the session's `_min_delay` increases by 1.0s up to 10s cap. Brain is not automatically notified — it should read the returned `AnalyzedResponse.is_waf_block` field.

**Eyes isolated contexts** (`eyes.py:198`): every `new_page(isolated=True)` creates a fresh Playwright browser context. This prevents cookie leakage across Brain tool calls. Pass `isolated=False` to share cookies (not used by current BrowserRenderTool).

**X-Ray MitmProxy lifecycle**: requires `mitmproxy` runtime. `MitmProxy.is_available()` static check lets InterceptProxyTool fail gracefully on hosts without it.

## What Phase A deliberately does NOT use

The Brain's Strix-power tools (`shell_exec` + `python_exec`) make HTTP requests via their OWN clients inside the sandbox (curl, sqlmap's requests, custom python httpx), **not through the primitives in this folder**. This means:

- `shell_exec curl http://target/` does NOT increment hands' `_request_count`
- sqlmap does NOT go through the CSRF auto-injection in `hands.py`
- No `_analyze_response` happens for sandbox-side traffic

For Phase A benchmarking this is by design ("real hacker simulation"). Phase C will need an egress filter on the sandbox to replicate enterprise audit logs at the network layer instead of the Hands layer.

## Do NOT use raw `httpx`

Per `CLAUDE.md` rules: **raw `httpx` is forbidden**. All in-process HTTP must go through `SessionManager.get_session().request()`. The Brain-driven path respects this (via `http_request` tool → `_session_manager` singleton). The sandbox path (shell_exec/python_exec) is exempt because it's architecturally outside the VXIS Python process.
