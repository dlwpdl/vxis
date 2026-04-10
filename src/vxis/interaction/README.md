# `src/vxis/interaction/` — Hands / Eyes / X-Ray Primitives

> The physical execution layer. Raw HTTP, headless browser, MitM proxy — wrapped by BrainTool adapters in `agent/tools/`.

## Four primitives

| File | Class | Role | BrainTool wrappers |
|---|---|---|---|
| `hands.py` | `SessionManager` + `TargetSession` + `RequestChain` + `_analyze_response` | HTTP client with session pooling, auth state tracking, CSRF auto-injection, response analysis (forms/links/WAF detection), adaptive timeout. | `HttpRequestTool` (`http_request`) |
| `eyes.py` | `BrowserEngine` + `BrowserPage` + `DOMAnalysis` + `PageSnapshot` | Playwright-backed headless browser. DOM snapshot, JS execution, form fill, screenshot. | `BrowserRenderTool` (legacy), **7 browser_* tools** (Phase C/D) |
| `xray.py` | `FlowAnalyzer` + `MitmProxy` + `CapturedFlow` + `InterceptRule` | MitM HTTP proxy for passive traffic capture + active response rewriting. Auth flow / API flow / vulnerability pattern detection. | `InterceptProxyTool` (`intercept_proxy`) |
| `controller.py` | `InteractionController` | Intent-based auto-selector — picks the right primitive for a given intent. Legacy: used by old pipeline.py. | (none; v2 uses primitives directly via BrainTools) |

## Eyes integration — Phase C/D browser tools

Phase C/D added 7 granular browser tools (`agent/tools/browser_tools.py`) wrapping the Eyes primitives:

| Tool | Eyes method |
|---|---|
| `browser_navigate` | `BrowserPage.navigate()` |
| `browser_analyze_dom` | `DOMAnalysis` — forms, links, scripts, hidden fields, meta |
| `browser_click` | `BrowserPage.click()` |
| `browser_fill_form` | `BrowserPage.fill()` + `submit()` |
| `browser_screenshot` | `BrowserPage.screenshot()` |
| `browser_eval_js` | `BrowserPage.evaluate()` |
| `browser_get_cookies` | `BrowserPage.cookies()` |

These use a **module-level singleton** `BrowserEngine` (shared across tool calls in a scan) instead of the legacy one-shot lifecycle (start → navigate → stop per call). This allows multi-step browser workflows: navigate → analyze DOM → fill form → screenshot.

The legacy `browser_render` tool (in `hands_tools.py`) still uses the one-shot lifecycle for backward compatibility.

## Key behaviors

**Hands adaptive timeout** (`hands.py`): after 2 consecutive timeout events, effective timeout multiplies by 1.5x up to `base_timeout * 1.5` cap. Prevents blind SQLi from paralyzing the scan.

**Hands CSRF auto-injection**: POST/PUT/PATCH/DELETE requests auto-get CSRF tokens from form fields, headers, and cookies.

**Hands WAF detection**: when `analyzed.is_waf_block` or `analyzed.is_rate_limited`, session delay increases by 1.0s up to 10s cap.

**Eyes isolated contexts** (`eyes.py`): `new_page(isolated=True)` creates a fresh browser context. Prevents cookie leakage across tool calls.

**X-Ray MitmProxy lifecycle**: requires `mitmproxy` runtime. `MitmProxy.is_available()` lets InterceptProxyTool fail gracefully on hosts without it.

## Sandbox traffic bypass

The Brain's Strix-power tools (`shell_exec` + `python_exec`) make HTTP requests via their OWN clients inside the Docker sandbox (curl, sqlmap, custom python httpx), **not through the primitives in this folder**. This means:

- `shell_exec curl http://target/` does NOT go through hands' CSRF auto-injection
- sqlmap does NOT increment hands' `_request_count`
- No `_analyze_response` for sandbox-side traffic

Enterprise egress filter (`src/vxis/agent/egress.py`) constrains sandbox outbound traffic when `VXIS_EGRESS_STRICT=1`.

## Do NOT use raw `httpx`

Per `CLAUDE.md` rules: **raw `httpx` is forbidden**. All in-process HTTP must go through `SessionManager.get_session().request()`. The sandbox path (shell_exec/python_exec) is exempt because it's architecturally outside the VXIS Python process.
