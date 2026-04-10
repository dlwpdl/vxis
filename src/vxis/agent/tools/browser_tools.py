"""Browser tools — Eyes integration for the Brain scan loop.

Wraps the existing `vxis.interaction.eyes` BrowserEngine so the Brain
can navigate to pages, see rendered DOM, fill forms, click elements,
analyze JS-rendered SPAs, and capture screenshots — all as tool calls
within the ReAct loop.

Design: a module-level singleton BrowserEngine is lazily started on
first `browser_navigate` call and reused across the entire scan.
Cleanup is triggered via `shutdown_browser()` called at scan end.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

# Module-level singleton — shared across all tool calls in a scan.
_engine: Any = None       # BrowserEngine
_page: Any = None         # BrowserPage
_screenshot_dir: str = ""


async def _ensure_browser() -> tuple[Any, Any]:
    """Lazily start BrowserEngine and create a page."""
    global _engine, _page, _screenshot_dir
    if _engine is not None and _page is not None:
        return _engine, _page

    from vxis.interaction.eyes import BrowserEngine, is_available
    if not is_available():
        raise RuntimeError(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )

    _screenshot_dir = tempfile.mkdtemp(prefix="vxis_screenshots_")
    _engine = BrowserEngine(headless=True)
    await _engine.start()
    _page = await _engine.new_page(isolated=False)
    logger.info("Browser started for scan (screenshots → %s)", _screenshot_dir)
    return _engine, _page


async def shutdown_browser() -> None:
    """Cleanup — called at scan end by ScanPipelineV2."""
    global _engine, _page
    if _engine is not None:
        try:
            await _engine.stop()
        except Exception:
            logger.exception("Browser cleanup failed")
        _engine = None
        _page = None
        logger.info("Browser shut down")


def _truncate(s: str, limit: int = 3000) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n... [truncated, total {len(s)} chars]"


# ── Tool: browser_navigate ───────────────────────────────────────


class BrowserNavigateTool:
    name = "browser_navigate"
    description = (
        "Navigate the browser to a URL and return a snapshot of the "
        "rendered page: title, visible text, forms (with fields), links, "
        "input elements, cookies, JS errors, and network requests. "
        "Use this instead of http_request when you need to see the "
        "RENDERED page (JavaScript executed, SPA loaded). First call "
        "starts the browser automatically."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL to navigate to"},
        },
        "required": ["url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        url = str(kwargs.get("url", "")).strip()
        if not url:
            return ToolResult(ok=False, summary="browser_navigate: url required", error="missing_url")

        try:
            _, page = await _ensure_browser()
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_navigate: browser init failed: {e}", error=str(e))

        try:
            snap = await page.navigate(url)
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_navigate: navigation failed: {e}", error=str(e))

        # Build a compact summary for the Brain
        forms_summary = []
        for f in snap.forms[:10]:
            fields = f.get("fields", {})
            field_names = list(fields.keys())[:8]
            forms_summary.append({
                "action": f.get("action", ""),
                "method": f.get("method", "GET"),
                "id": f.get("id", ""),
                "fields": field_names,
            })

        network_summary = []
        for entry in snap.network_log[-20:]:
            if entry.resource_type in ("document", "xhr", "fetch"):
                network_summary.append({
                    "method": entry.method,
                    "url": entry.url[:200],
                    "status": entry.status,
                    "type": entry.resource_type,
                })

        return ToolResult(
            ok=True,
            data={
                "url": snap.url,
                "title": snap.title,
                "text_content": _truncate(snap.text_content, 4000),
                "forms": forms_summary,
                "form_count": len(snap.forms),
                "links": snap.links[:30],
                "link_count": len(snap.links),
                "inputs": snap.inputs[:20],
                "cookies": [{"name": c.get("name", ""), "domain": c.get("domain", "")} for c in snap.cookies[:15]],
                "js_errors": snap.js_errors[:10],
                "console_messages": snap.console_messages[-10:],
                "network_requests": network_summary,
            },
            summary=(
                f"browser: {snap.title} ({snap.url}) — "
                f"{len(snap.forms)} form(s), {len(snap.links)} link(s), "
                f"{len(snap.inputs)} input(s), {len(snap.cookies)} cookie(s), "
                f"{len(snap.js_errors)} JS error(s)"
            ),
        )


# ── Tool: browser_analyze_dom ────────────────────────────────────


class BrowserAnalyzeDomTool:
    name = "browser_analyze_dom"
    description = (
        "Deep-analyze the currently loaded page's DOM. Returns: login "
        "forms, file upload forms, API endpoints found in inline JS, "
        "hidden inputs, HTML comments, and meta tags. Call this AFTER "
        "browser_navigate to extract attack surface from the rendered page."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        if _page is None:
            return ToolResult(ok=False, summary="browser_analyze_dom: no page loaded — call browser_navigate first", error="no_page")

        try:
            dom = await _page.analyze_dom()
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_analyze_dom: {e}", error=str(e))

        return ToolResult(
            ok=True,
            data={
                "login_forms": dom.login_forms[:5],
                "file_uploads": dom.file_uploads[:5],
                "api_endpoints": dom.api_endpoints[:30],
                "hidden_inputs": dom.hidden_inputs[:15],
                "comments": dom.comments[:10],
                "inline_script_count": len(dom.inline_scripts),
                "inline_scripts_preview": [s[:300] for s in dom.inline_scripts[:5]],
                "meta_info": dict(list(dom.meta_info.items())[:15]),
                "all_forms": dom.forms[:10],
            },
            summary=(
                f"DOM analysis: {len(dom.login_forms)} login form(s), "
                f"{len(dom.file_uploads)} upload(s), "
                f"{len(dom.api_endpoints)} API endpoint(s), "
                f"{len(dom.hidden_inputs)} hidden input(s), "
                f"{len(dom.comments)} comment(s)"
            ),
        )


# ── Tool: browser_click ──────────────────────────────────────────


class BrowserClickTool:
    name = "browser_click"
    description = (
        "Click an element on the current page by CSS selector. Returns "
        "the page state after the click (title, URL, new forms/links). "
        "Use for: clicking buttons, navigating links, submitting forms."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "selector": {"type": "string", "description": "CSS selector (e.g. 'button#login', 'a.nav-link')"},
        },
        "required": ["selector"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        selector = str(kwargs.get("selector", "")).strip()
        if not selector:
            return ToolResult(ok=False, summary="browser_click: selector required", error="missing_selector")
        if _page is None:
            return ToolResult(ok=False, summary="browser_click: no page loaded", error="no_page")

        try:
            await _page.click(selector)
            snap = await _page.snapshot()
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_click: {e}", error=str(e))

        return ToolResult(
            ok=True,
            data={
                "url": snap.url,
                "title": snap.title,
                "text_preview": _truncate(snap.text_content, 2000),
                "form_count": len(snap.forms),
                "link_count": len(snap.links),
            },
            summary=f"clicked '{selector}' → {snap.title} ({snap.url})",
        )


# ── Tool: browser_fill_form ──────────────────────────────────────


class BrowserFillFormTool:
    name = "browser_fill_form"
    description = (
        "Fill a form on the current page. Provide the form selector and "
        "a dict of field_name→value pairs. After filling, optionally "
        "click the submit button. Use for: login attempts, search, "
        "registration, file upload prep."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "form_selector": {
                "type": "string",
                "description": "CSS selector for the form (e.g. 'form#login', 'form:first-of-type')",
            },
            "fields": {
                "type": "object",
                "description": "Dict of field_name → value (e.g. {\"username\": \"admin\", \"password\": \"admin123\"})",
            },
            "submit_selector": {
                "type": "string",
                "description": "Optional CSS selector for submit button. If provided, clicks it after filling.",
            },
        },
        "required": ["form_selector", "fields"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        form_sel = str(kwargs.get("form_selector", "")).strip()
        fields = kwargs.get("fields", {})
        submit_sel = str(kwargs.get("submit_selector", "") or "").strip()

        if not form_sel or not fields:
            return ToolResult(ok=False, summary="browser_fill_form: form_selector and fields required", error="missing_args")
        if _page is None:
            return ToolResult(ok=False, summary="browser_fill_form: no page loaded", error="no_page")

        try:
            await _page.fill_form(form_sel, fields)
            if submit_sel:
                await _page.click(submit_sel)
                # Wait for navigation/response
                try:
                    await _page.wait_for_navigation(timeout=5000)
                except Exception:
                    pass
            snap = await _page.snapshot()
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_fill_form: {e}", error=str(e))

        return ToolResult(
            ok=True,
            data={
                "url": snap.url,
                "title": snap.title,
                "text_preview": _truncate(snap.text_content, 2000),
                "cookies": [{"name": c.get("name", ""), "value": c.get("value", "")[:50]} for c in snap.cookies[:10]],
                "form_count": len(snap.forms),
                "js_errors": snap.js_errors[:5],
            },
            summary=(
                f"filled form '{form_sel}' with {len(fields)} field(s)"
                + (f", clicked '{submit_sel}'" if submit_sel else "")
                + f" → {snap.title} ({snap.url})"
            ),
        )


# ── Tool: browser_screenshot ─────────────────────────────────────


class BrowserScreenshotTool:
    name = "browser_screenshot"
    description = (
        "Take a screenshot of the current page. Returns the file path. "
        "Useful for visual verification or capturing evidence of a "
        "vulnerability exploit."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "filename": {"type": "string", "description": "Filename for screenshot (default: auto-generated)"},
            "full_page": {"type": "boolean", "description": "Capture full page vs viewport only (default: true)"},
        },
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        if _page is None:
            return ToolResult(ok=False, summary="browser_screenshot: no page loaded", error="no_page")

        filename = str(kwargs.get("filename", "")).strip()
        full_page = bool(kwargs.get("full_page", True))

        if not filename:
            import time
            filename = f"screenshot_{int(time.time())}.png"

        path = os.path.join(_screenshot_dir, filename)

        try:
            await _page.screenshot(path=path, full_page=full_page)
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_screenshot: {e}", error=str(e))

        size = os.path.getsize(path)
        return ToolResult(
            ok=True,
            data={"path": path, "size": size, "filename": filename},
            summary=f"screenshot saved: {path} ({size} bytes)",
        )


# ── Tool: browser_eval_js ────────────────────────────────────────


class BrowserEvalJsTool:
    name = "browser_eval_js"
    description = (
        "Execute JavaScript on the current page. Returns the result. "
        "Use for: checking localStorage/sessionStorage, extracting "
        "tokens, testing XSS payloads, reading DOM properties."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "expression": {
                "type": "string",
                "description": "JavaScript expression to evaluate (e.g. 'document.cookie', 'localStorage.getItem(\"token\")')",
            },
        },
        "required": ["expression"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        expr = str(kwargs.get("expression", "")).strip()
        if not expr:
            return ToolResult(ok=False, summary="browser_eval_js: expression required", error="missing_expression")
        if _page is None:
            return ToolResult(ok=False, summary="browser_eval_js: no page loaded", error="no_page")

        try:
            result = await _page.evaluate(expr)
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_eval_js: {e}", error=str(e))

        # Serialize result
        if isinstance(result, (dict, list)):
            result_str = json.dumps(result, default=str, ensure_ascii=False)[:3000]
        else:
            result_str = str(result)[:3000]

        return ToolResult(
            ok=True,
            data={"result": result, "result_str": result_str},
            summary=f"JS eval → {result_str[:200]}",
        )


# ── Tool: browser_get_cookies ────────────────────────────────────


class BrowserGetCookiesTool:
    name = "browser_get_cookies"
    description = (
        "Get all cookies from the current browser session. Useful for: "
        "checking session tokens, JWT values, CSRF tokens after login."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        if _page is None:
            return ToolResult(ok=False, summary="browser_get_cookies: no page loaded", error="no_page")

        try:
            cookies = await _page.get_cookies()
        except Exception as e:
            return ToolResult(ok=False, summary=f"browser_get_cookies: {e}", error=str(e))

        return ToolResult(
            ok=True,
            data={"cookies": cookies},
            summary=f"{len(cookies)} cookie(s): {', '.join(c.get('name','') for c in cookies[:10])}",
        )
