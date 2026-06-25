"""Hands/Eyes/X-Ray BrainTool adapters (Task 6).

Thin wrappers around VXIS interaction primitives so the ScanAgentLoop can
invoke them as tools. No reimplementation of underlying logic.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from vxis.agent.tool_registry import ToolResult
from vxis.interaction.hands import SessionManager
from vxis.agent.tools.proxy_runtime import (
    get_active_proxy_url,
    get_proxy_runtime,
    reset_proxy_runtime_for_tests,
)
from vxis.ghost.routing import build_browser_ghost_route, ghost_transport_metadata

# ── Module-level singletons ─────────────────────────────────────────────
# Session + proxy state must persist across tool calls within a scan so
# auth cookies, CSRF tokens, captured flows, etc. aren't lost.

_session_manager: SessionManager | None = None


def _get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def _reset_for_tests() -> None:
    """Reset module-level state. Called from test fixtures, NOT production code."""
    global _session_manager
    _session_manager = None
    reset_proxy_runtime_for_tests()


async def import_browser_cookies(
    base_url: str,
    cookies: list[dict[str, Any]],
    *,
    identity: str | None = None,
) -> int:
    """Bridge Playwright cookies into the shared http_request session."""
    if not base_url or not cookies:
        return 0
    parsed = urlparse(base_url)
    if parsed.scheme and parsed.netloc:
        base_url = f"{parsed.scheme}://{parsed.netloc}"
    return await _get_session_manager().import_cookies(
        base_url,
        cookies,
        identity=identity,
        proxy=get_active_proxy_url(),
    )


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
            "identity": {
                "type": "string",
                "description": "Optional principal/session label for multi-identity authz testing.",
            },
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
        identity = str(kwargs.get("identity") or "").strip() or None

        if not base_url:
            return ToolResult(
                ok=False,
                summary="http_request: base_url or url is required",
                error="missing_base_url",
            )

        try:
            mgr = _get_session_manager()
            session = await mgr.get_session(
                base_url,
                identity=identity,
                proxy=get_active_proxy_url(),
            )
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
                "identity": identity or "default",
                "ghost": ghost_transport_metadata("http_request"),
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
            proxy, user_agent, ghost_meta = build_browser_ghost_route(
                "browser_render",
                capture_proxy=get_active_proxy_url(),
            )
            engine = BrowserEngine(proxy=proxy, user_agent=user_agent)
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
                "ghost": ghost_meta,
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
        "Control the live HTTP proxy runtime used by VXIS. Supports X-Ray "
        "(embedded mitmproxy) and optional external Caido attachment. "
        "Actions: 'start', 'stop', 'status', 'list_requests', "
        "'view_request', 'repeat_request', 'scope_rules', "
        "'list_sitemap', 'view_sitemap_entry'. "
        "'flows' remains as a compatibility alias for 'list_requests'."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "start",
                    "stop",
                    "status",
                    "flows",
                    "list_requests",
                    "view_request",
                    "repeat_request",
                    "scope_rules",
                    "list_sitemap",
                    "view_sitemap_entry",
                ],
            },
            "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
            "backend": {"type": "string", "enum": ["auto", "xray", "caido"]},
            "filter": {"type": "string"},
            "request_id": {"type": "string"},
            "part": {"type": "string", "enum": ["request", "response"]},
            "page": {"type": "integer", "minimum": 1},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 200},
            "overrides": {"type": "object"},
            "scope_action": {"type": "string", "enum": ["get", "set", "update", "clear"]},
            "allowlist": {"type": "array", "items": {"type": "string"}},
            "denylist": {"type": "array", "items": {"type": "string"}},
            "entry_id": {"type": "string"},
        },
        "required": ["action"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "")
        port = int(kwargs.get("port", 8081))
        runtime = get_proxy_runtime()
        backend = str(kwargs.get("backend") or "auto").strip().lower() or "auto"
        filter_expr = str(kwargs.get("filter") or "").strip()
        page = int(kwargs.get("page") or 1)
        page_size = int(kwargs.get("page_size") or 20)

        if action == "start":
            try:
                status = await runtime.start(port=port, backend=backend)
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy start failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            if status.get("running"):
                return ToolResult(
                    ok=True,
                    data=status,
                    summary=(
                        f"intercept_proxy started ({status.get('backend')}) on "
                        f"{status.get('proxy_url') or 'attached backend'}"
                    ),
                )
            err = status.get("last_error") or "proxy_unavailable"
            return ToolResult(
                ok=False,
                data=status,
                summary=f"intercept_proxy unavailable: {err}",
                error=str(err),
            )

        if action == "stop":
            try:
                status = await runtime.stop()
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy stop failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            return ToolResult(ok=True, data=status, summary="intercept_proxy stopped")

        if action == "status":
            status = runtime.status()
            return ToolResult(
                ok=True,
                data=status,
                summary=(
                    f"proxy {status.get('backend')} "
                    f"{'running' if status.get('running') else 'stopped'} "
                    f"({status.get('flow_count', 0)} flow(s))"
                ),
            )

        if action in {"flows", "list_requests"}:
            try:
                result = await runtime.list_requests(
                    filter_expr=filter_expr,
                    page=page,
                    page_size=page_size,
                )
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy list_requests failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            return ToolResult(
                ok=True,
                data=result,
                summary=(
                    f"intercept_proxy listed {result.get('count', 0)} request(s) "
                    f"(total {result.get('total_count', 0)})"
                ),
            )

        if action == "view_request":
            request_id = str(kwargs.get("request_id") or "").strip()
            part = str(kwargs.get("part") or "request").strip()
            if not request_id:
                return ToolResult(ok=False, summary="intercept_proxy: request_id required", error="missing_request_id")
            try:
                result = await runtime.view_request(request_id, part=part)
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy view_request failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            if result.get("error"):
                return ToolResult(ok=False, data=result, summary=str(result["error"]), error=str(result["error"]))
            return ToolResult(
                ok=True,
                data=result,
                summary=f"intercept_proxy viewed {part} for {request_id}",
            )

        if action == "repeat_request":
            request_id = str(kwargs.get("request_id") or "").strip()
            if not request_id:
                return ToolResult(ok=False, summary="intercept_proxy: request_id required", error="missing_request_id")
            overrides = kwargs.get("overrides") or {}
            try:
                result = await runtime.repeat_request(request_id, overrides=overrides)
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy repeat_request failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            if not result.get("ok", False):
                err = result.get("error") or "repeat_request_failed"
                return ToolResult(ok=False, data=result, summary=str(err), error=str(err))
            preview = _tool_json_preview(result)
            return ToolResult(
                ok=True,
                data=result,
                summary=(
                    f"replayed {request_id} → {result.get('status_code')} "
                    f"{preview}"
                ),
            )

        if action == "scope_rules":
            scope_action = str(kwargs.get("scope_action") or "get").strip().lower() or "get"
            try:
                result = await runtime.scope_rules(
                    action=scope_action,
                    allowlist=kwargs.get("allowlist"),
                    denylist=kwargs.get("denylist"),
                )
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy scope_rules failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            return ToolResult(
                ok=True,
                data=result,
                summary=(
                    f"proxy scope {scope_action}: "
                    f"allow={len((result.get('scope') or {}).get('allowlist', []))} "
                    f"deny={len((result.get('scope') or {}).get('denylist', []))}"
                ),
            )

        if action == "list_sitemap":
            try:
                result = await runtime.list_sitemap()
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy list_sitemap failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            return ToolResult(
                ok=True,
                data=result,
                summary=f"proxy sitemap entries: {result.get('count', 0)}",
            )

        if action == "view_sitemap_entry":
            entry_id = str(kwargs.get("entry_id") or "").strip()
            if not entry_id:
                return ToolResult(ok=False, summary="intercept_proxy: entry_id required", error="missing_entry_id")
            try:
                result = await runtime.view_sitemap_entry(entry_id)
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"intercept_proxy view_sitemap_entry failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            if result.get("error"):
                return ToolResult(ok=False, data=result, summary=str(result["error"]), error=str(result["error"]))
            return ToolResult(
                ok=True,
                data=result,
                summary=f"proxy sitemap entry {entry_id} has {result.get('request_count', 0)} request(s)",
            )

        return ToolResult(
            ok=False,
            summary=f"intercept_proxy: unknown action '{action}'",
            error="unknown_action",
        )


def _tool_json_preview(data: dict[str, Any]) -> str:
    try:
        return _truncate_json(json.dumps(data, ensure_ascii=False, default=str))
    except Exception:
        return ""


def _truncate_json(text: str, limit: int = 80) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."
