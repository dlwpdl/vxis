"""Sensing primitives — HTTP / browser / traffic capture.

Thin wrappers over vxis.interaction.hands, eyes, xray. No LLM calls.
All functions are pure tool invocations.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from vxis.interaction.hands import SessionManager, TargetSession

logger = logging.getLogger(__name__)

# ── Module-level singleton session manager ────────────────────────
_session_manager: SessionManager | None = None
# Session id → TargetSession cache for probe() reuse.
_session_cache: dict[str, TargetSession] = {}
# X-Ray mitmproxy managers keyed by session id.
_xray_managers: dict[str, Any] = {}


def _get_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def _session_id_for(target: str) -> str:
    """Derive a stable session id from a target URL."""
    return urlparse(target).netloc or target


# ── Crawl ─────────────────────────────────────────────────────────


async def primitive_crawl(
    target: str,
    depth: int = 3,
    stealth_level: int = 3,
) -> dict:
    """Crawl a target and return discovered endpoints, forms, and links.

    Args:
        target: Base URL of the target.
        depth: Maximum link-follow depth (1-5).
        stealth_level: 1=fast, 5=very slow. Currently advisory.

    Returns:
        dict with keys: endpoints, forms, links, tech, pages_visited.
    """
    mgr = _get_manager()
    session = await mgr.get_session(target)
    _session_cache[_session_id_for(target)] = session

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [("/", 0)]
    forms_out: list[dict] = []
    links_out: set[str] = set()
    tech_out: set[str] = set()
    base_host = urlparse(target).netloc

    max_pages = max(5, min(depth * 20, 200))

    while queue and len(visited) < max_pages:
        path, d = queue.pop(0)
        if path in visited or d > depth:
            continue
        visited.add(path)
        try:
            analyzed = await session.get(path)
        except Exception as exc:
            logger.debug("crawl GET %s failed: %s", path, exc)
            continue

        for t in analyzed.detected_tech:
            if t:
                tech_out.add(t)

        for form in analyzed.forms:
            forms_out.append(
                {
                    "action": getattr(form, "action", ""),
                    "method": getattr(form, "method", "GET"),
                    "inputs": getattr(form, "inputs", []),
                }
            )

        for link in analyzed.links:
            links_out.add(link)
            parsed = urlparse(link)
            if parsed.netloc == "" or parsed.netloc == base_host:
                next_path = parsed.path or "/"
                if next_path not in visited:
                    queue.append((next_path, d + 1))

    endpoints = sorted(visited)
    return {
        "target": target,
        "endpoints": endpoints,
        "forms": forms_out,
        "links": sorted(links_out),
        "tech": sorted(tech_out),
        "pages_visited": len(visited),
    }


# ── Probe ─────────────────────────────────────────────────────────


async def primitive_probe(
    session_id: str,
    method: str,
    url: str,
    headers: dict | None = None,
    body: dict | None = None,
    stealth_level: int = 3,
) -> dict:
    """Send a single HTTP request via an existing session and return raw response.

    Args:
        session_id: Id returned from primitive_crawl or session_create.
        method: HTTP verb (GET/POST/PUT/DELETE/PATCH).
        url: Absolute URL or path relative to the session base URL.
        headers: Optional extra headers.
        body: Optional JSON-serializable body. Sent as form data.

    Returns:
        dict with keys: status, headers, body, url, timing_ms, content_type.
    """
    session = _session_cache.get(session_id)
    if session is None:
        mgr = _get_manager()
        # Treat session_id as base URL fallback.
        session = await mgr.get_session(url if "://" in url else f"http://{session_id}")
        _session_cache[session_id] = session

    import time

    t0 = time.monotonic()
    parsed = urlparse(url)
    path = url if parsed.netloc else url
    analyzed = await session.request(
        method=method,
        path=path,
        data=body if body and not isinstance(body, (str, bytes)) else None,
        headers=headers,
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    resp = analyzed.response
    try:
        body_text = resp.text
    except Exception:
        body_text = ""
    return {
        "status": analyzed.status,
        "headers": dict(resp.headers),
        "body": body_text,
        "url": analyzed.url,
        "timing_ms": elapsed_ms,
        "content_type": analyzed.content_type,
        "is_waf_block": analyzed.is_waf_block,
    }


async def primitive_probe_parallel(
    session_id: str,
    requests: list[dict],
    stealth_level: int = 3,
) -> list[dict]:
    """Execute multiple probes concurrently.

    Args:
        session_id: Session id.
        requests: List of dicts each with keys {method, url, headers?, body?}.
        stealth_level: Passed through to primitive_probe.

    Returns:
        List of response dicts, in the same order as `requests`.
    """
    import asyncio

    tasks = [
        primitive_probe(
            session_id=session_id,
            method=r.get("method", "GET"),
            url=r["url"],
            headers=r.get("headers"),
            body=r.get("body"),
            stealth_level=stealth_level,
        )
        for r in requests
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[dict] = []
    for r in results:
        if isinstance(r, Exception):
            out.append({"status": 0, "error": str(r), "body": "", "headers": {}})
        else:
            out.append(r)  # type: ignore[arg-type]
    return out


# ── Fingerprint ────────────────────────────────────────────────────


async def primitive_fingerprint(target: str) -> dict:
    """Fingerprint the target's technology stack from headers and HTML markers.

    Returns:
        dict with keys: server, tech, headers, title, cookies.
    """
    mgr = _get_manager()
    session = await mgr.get_session(target)
    _session_cache[_session_id_for(target)] = session
    analyzed = await session.get("/")
    resp = analyzed.response

    try:
        body = resp.text
    except Exception:
        body = ""

    title = ""
    import re

    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    if m:
        title = m.group(1).strip()

    return {
        "target": target,
        "status": analyzed.status,
        "server": resp.headers.get("server", ""),
        "tech": analyzed.detected_tech,
        "headers": dict(resp.headers),
        "title": title,
        "cookies": analyzed.cookies_set,
        "security_headers": analyzed.security_headers,
    }


# ── Subdomain enumeration ─────────────────────────────────────────


_COMMON_SUBDOMAINS = (
    "www", "api", "dev", "staging", "test", "admin", "mail", "webmail",
    "blog", "shop", "store", "app", "beta", "m", "mobile", "secure",
    "vpn", "remote", "portal", "support", "help", "docs", "status",
    "cdn", "static", "assets", "img", "images", "media", "files",
    "ftp", "sftp", "ssh", "ns1", "ns2", "mx", "smtp", "pop", "imap",
    "cpanel", "whm", "jenkins", "git", "gitlab", "jira", "confluence",
    "grafana", "prometheus", "kibana", "elastic", "consul", "vault",
)


async def primitive_subdomain_enum(
    domain: str,
    wordlist: str = "common",
) -> list[str]:
    """Enumerate subdomains via DNS resolution against a wordlist.

    Args:
        domain: Apex domain (e.g. "example.com").
        wordlist: "common" uses the built-in 50-word list.

    Returns:
        List of subdomains that resolved successfully.
    """
    import asyncio
    import socket

    words = _COMMON_SUBDOMAINS

    async def _check(sub: str) -> str | None:
        host = f"{sub}.{domain}"
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, socket.gethostbyname, host)
            return host
        except Exception:
            return None

    results = await asyncio.gather(*(_check(w) for w in words))
    return sorted(h for h in results if h)


# ── Screenshot ─────────────────────────────────────────────────────


async def primitive_screenshot(url: str, viewport: str = "1920x1080") -> str:
    """Capture a full-page screenshot via headless Chromium and return the file path.

    Args:
        url: Page to load.
        viewport: WxH viewport string (e.g. "1920x1080").

    Returns:
        Absolute path to the saved PNG.
    """
    import tempfile
    from pathlib import Path

    from vxis.interaction.eyes import BrowserEngine, is_available

    if not is_available():
        raise RuntimeError("Playwright not available — install: pip install playwright && playwright install chromium")

    try:
        w_str, h_str = viewport.lower().split("x")
        w, h = int(w_str), int(h_str)
    except Exception:
        w, h = 1920, 1080

    out_path = Path(tempfile.mkdtemp(prefix="vxis-shot-")) / "screenshot.png"

    async with BrowserEngine() as engine:
        page = await engine.new_page()
        try:
            await page._page.set_viewport_size({"width": w, "height": h})  # noqa: SLF001
        except Exception:
            pass
        await page.navigate(url)
        await page._page.screenshot(path=str(out_path), full_page=True)  # noqa: SLF001

    return str(out_path)


# ── X-Ray traffic capture ──────────────────────────────────────────


async def primitive_xray_start(target: str) -> str:
    """Start an mitmproxy capture session and return its session id.

    The caller should route subsequent traffic through the reported proxy URL.
    """
    from vxis.interaction.xray import MitmProxyManager

    mgr = MitmProxyManager()
    await mgr.start()
    sid = f"xray-{_session_id_for(target)}-{id(mgr)}"
    _xray_managers[sid] = mgr
    return sid


async def primitive_xray_flows(session_id: str, filter: str = "") -> list[dict]:
    """Return captured traffic flows from a running X-Ray session.

    Args:
        session_id: Id returned from primitive_xray_start.
        filter: Optional substring filter applied to the URL.

    Returns:
        List of flow dicts with {method, url, status, request_headers, response_headers, body}.
    """
    mgr = _xray_managers.get(session_id)
    if mgr is None:
        return []
    flows = mgr.get_captured_flows()
    out: list[dict] = []
    for f in flows:
        url = getattr(f, "url", "")
        if filter and filter not in url:
            continue
        out.append(
            {
                "id": getattr(f, "id", ""),
                "method": getattr(f, "method", ""),
                "url": url,
                "status": getattr(f, "status_code", 0),
                "request_headers": getattr(f, "request_headers", {}),
                "response_headers": getattr(f, "response_headers", {}),
                "request_body": getattr(f, "request_body", ""),
                "response_body": getattr(f, "response_body", ""),
            }
        )
    return out
