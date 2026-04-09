"""Hands/Eyes/X-Ray BrainTool adapters (Task 6).

Thin wrappers around VXIS interaction primitives so the ScanAgentLoop can
invoke them as tools. No reimplementation of underlying logic.
"""
from __future__ import annotations

from typing import Any

from vxis.agent.tool_registry import ToolResult
from vxis.interaction.hands import SessionManager

# ── Module-level singletons ─────────────────────────────────────────────
# Session + proxy state must persist across tool calls within a scan so
# auth cookies, CSRF tokens, captured flows, etc. aren't lost.

_session_manager: SessionManager | None = None
_mitm_proxy: Any = None
_flow_analyzer: Any = None


def _get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def _reset_for_tests() -> None:
    """Reset module-level state. Called from test fixtures, NOT production code."""
    global _session_manager, _mitm_proxy, _flow_analyzer
    _session_manager = None
    _mitm_proxy = None
    _flow_analyzer = None


# ── HttpRequestTool ─────────────────────────────────────────────────────

class HttpRequestTool:
    name = "http_request"
    description = (
        "Send an HTTP request to the target via the shared VXIS SessionManager. "
        "Auth cookies and CSRF tokens persist across calls within the same scan. "
        "Accepts either `url` (full URL) OR `base_url` + `path` (split form)."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Full URL (scheme+host+port+path+query). Alternative to base_url+path.",
            },
            "base_url": {
                "type": "string",
                "description": "Target base URL (scheme+host+port). Required if `url` not given.",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                "default": "GET",
            },
            "path": {
                "type": "string",
                "description": "Path+query. Required if `url` not given.",
            },
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "params": {"type": "object", "additionalProperties": {"type": "string"}},
            "data": {"type": "object"},
            "json": {"type": "object"},
        },
        "required": ["method"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        base_url = kwargs.get("base_url", "")
        path = kwargs.get("path", "")
        url_arg = kwargs.get("url", "")

        # Phase B fix: accept `url` as an alternative to base_url+path.
        # Brain frequently emits {"url": "http://..."} naturally, so auto-split.
        if url_arg and not base_url:
            from urllib.parse import urlparse
            parsed = urlparse(url_arg)
            if parsed.scheme and parsed.netloc:
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                split_path = parsed.path or "/"
                if parsed.query:
                    split_path = f"{split_path}?{parsed.query}"
                path = split_path
            else:
                return ToolResult(
                    ok=False,
                    summary=f"http_request: invalid url '{url_arg[:100]}'",
                    error="invalid_url",
                )

        if not path:
            path = "/"

        method = kwargs.get("method", "GET")
        headers = kwargs.get("headers") or None
        params = kwargs.get("params") or None
        data = kwargs.get("data") or None
        json_data = kwargs.get("json") or None

        if not base_url:
            return ToolResult(
                ok=False,
                summary="http_request: base_url or url is required",
                error="missing_base_url",
            )

        try:
            mgr = _get_session_manager()
            session = await mgr.get_session(base_url)
            resp = await session.request(
                method=method,
                path=path,
                data=data,
                json_data=json_data,
                headers=headers,
                params=params,
            )
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"http_request failed: {type(e).__name__}: {e}",
                error=str(e),
            )

        body_preview = ""
        try:
            body = getattr(resp, "body", "") or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            body_preview = body[:500]
        except Exception:
            body_preview = ""

        return ToolResult(
            ok=True,
            data={
                "status": getattr(resp, "status", 0),
                "body_preview": body_preview,
                "body_length": getattr(resp, "body_length", 0),
                "headers": dict(getattr(resp, "headers", {}) or {}),
                "links": list(getattr(resp, "links", []) or [])[:20],
                "forms_count": len(getattr(resp, "forms", []) or []),
            },
            summary=f"{method} {path} → {getattr(resp, 'status', '?')} ({getattr(resp, 'body_length', 0)} bytes)",
        )


# ── BrowserRenderTool ───────────────────────────────────────────────────

class BrowserRenderTool:
    name = "browser_render"
    description = (
        "Render a URL in a headless browser and return DOM snapshot (JS executed). "
        "Use for SPAs (Angular/React/Vue) where http_request only sees the shell HTML."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Fully qualified URL to render"},
        },
        "required": ["url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        if not url:
            return ToolResult(
                ok=False,
                summary="browser_render: url is required",
                error="missing_url",
            )

        try:
            from vxis.interaction.eyes import BrowserEngine
        except ImportError as e:
            return ToolResult(
                ok=False,
                summary="browser_render unavailable: playwright not installed",
                error=f"ImportError: {e}",
            )

        try:
            engine = BrowserEngine()
            await engine.start()
            try:
                page = await engine.new_page()
                await page.navigate(url)
                snap = await page.snapshot()
            finally:
                await engine.stop()
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"browser_render failed: {type(e).__name__}: {e}",
                error=str(e),
            )

        title = getattr(snap, "title", "") or ""
        final_url = getattr(snap, "url", url) or url
        links = list(getattr(snap, "links", []) or [])[:20]
        forms = list(getattr(snap, "forms", []) or [])
        html_len = len(getattr(snap, "html", "") or "")

        return ToolResult(
            ok=True,
            data={
                "title": title,
                "final_url": final_url,
                "html_length": html_len,
                "links": links,
                "forms_count": len(forms),
            },
            summary=(
                f"rendered {url} → title='{title[:50]}' "
                f"({html_len} bytes, {len(links)} links, {len(forms)} forms)"
            ),
        )


# ── InterceptProxyTool ──────────────────────────────────────────────────

class InterceptProxyTool:
    name = "intercept_proxy"
    description = (
        "Control the X-Ray mitmproxy for passive traffic capture. "
        "Actions: 'start' (begin capture on a port), 'stop' (end capture), "
        "'flows' (list captured flows summary)."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["start", "stop", "flows"]},
            "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
        },
        "required": ["action"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        global _mitm_proxy, _flow_analyzer
        action = kwargs.get("action", "")
        port = int(kwargs.get("port", 8081))

        try:
            # X-Ray exports MitmProxyManager (not MitmProxy) — alias for clarity.
            from vxis.interaction.xray import FlowAnalyzer, MitmProxyManager as MitmProxy
        except ImportError as e:
            return ToolResult(
                ok=False,
                summary="intercept_proxy unavailable: mitmproxy not installed",
                error=f"ImportError: {e}",
            )

        if action == "start":
            if _mitm_proxy is not None:
                return ToolResult(
                    ok=True,
                    data={
                        "already_running": True,
                        "proxy_url": getattr(_mitm_proxy, "proxy_url", None),
                    },
                    summary="intercept_proxy already running",
                )
            if not MitmProxy.is_available():
                return ToolResult(
                    ok=False,
                    summary="intercept_proxy unavailable: mitmproxy runtime not installed",
                    error="mitmproxy_not_available",
                )
            try:
                _flow_analyzer = FlowAnalyzer()
                _mitm_proxy = MitmProxy(port=port)
                proxy_url = await _mitm_proxy.start()
                return ToolResult(
                    ok=True,
                    data={"proxy_url": proxy_url, "port": port},
                    summary=f"intercept_proxy started on {proxy_url}",
                )
            except Exception as e:
                _mitm_proxy = None
                _flow_analyzer = None
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy start failed: {type(e).__name__}: {e}",
                    error=str(e),
                )

        if action == "stop":
            if _mitm_proxy is None:
                return ToolResult(
                    ok=True,
                    data={"already_stopped": True},
                    summary="intercept_proxy already stopped",
                )
            try:
                await _mitm_proxy.stop()
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy stop failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            finally:
                _mitm_proxy = None
                _flow_analyzer = None
            return ToolResult(ok=True, summary="intercept_proxy stopped")

        if action == "flows":
            if _mitm_proxy is None:
                return ToolResult(
                    ok=True,
                    data={"flows": [], "count": 0},
                    summary="intercept_proxy not running (0 flows)",
                )
            try:
                flows = _mitm_proxy.get_captured_flows(_flow_analyzer)
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy flows failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            return ToolResult(
                ok=True,
                data={
                    "count": len(flows),
                    "flows_preview": [str(f)[:200] for f in flows[:10]],
                },
                summary=f"intercept_proxy captured {len(flows)} flows",
            )

        return ToolResult(
            ok=False,
            summary=f"intercept_proxy: unknown action '{action}'",
            error="unknown_action",
        )
