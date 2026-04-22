"""WebSurface — wraps SessionManager / BrowserEngine / MitmProxyManager / FlowAnalyzer
under the universal Hands / Eyes / XRay / Recon ABCs.

Phase-B keystone: lets Brain · Director · Phase code stay surface-agnostic. The
heavy lifting still lives in the existing modules; we just adapt their
signatures to the InteractionEnvelope / ReconReport contract.

Concrete kind dispatch happens in `factory.SurfaceFactory`.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from vxis.interaction.hands import AnalyzedResponse, SessionManager, TargetSession
from vxis.interaction.surface import (
    Eyes,
    Hands,
    InteractionEnvelope,
    Recon,
    ReconReport,
    Target,
    TargetKind,
    XRay,
)

logger = logging.getLogger(__name__)


class WebHands(Hands):
    """HTTP requests via the existing SessionManager → TargetSession path.

    `intent` carries the HTTP method ("GET", "POST", ...). All TargetSession.request
    kwargs (path, data, json_data, headers, params) flow through `**kw`.

    The controller can inject its own SessionManager so cookies, CSRF tokens,
    and auth state stay coherent across surface and direct-session callers.
    `last_response` exposes the most recent AnalyzedResponse so the controller
    can keep building rich InteractionResults from forms/links/error_patterns.
    """

    def __init__(self, target: Target, session_mgr: SessionManager | None = None) -> None:
        self._target = target
        self._mgr = session_mgr or SessionManager()
        self._owns_mgr = session_mgr is None
        self._session: TargetSession | None = None
        self.last_response: AnalyzedResponse | None = None

    async def start(self) -> None:
        if self._session is None:
            self._session = await self._mgr.get_session(self._target.entry)

    async def stop(self) -> None:
        try:
            if self._owns_mgr:
                await self._mgr.close_all()
        finally:
            self._session = None

    async def request(self, intent: str, **kw: object) -> InteractionEnvelope:
        if self._session is None:
            await self.start()
        assert self._session is not None  # narrows for type-checkers

        path = str(kw.pop("path", "/"))
        try:
            resp = await self._session.request(intent.upper(), path, **kw)  # type: ignore[arg-type]
        except Exception as exc:  # network failures, WAF aborts, etc.
            logger.warning("WebHands.request failed: %s %s — %s", intent, path, exc)
            self.last_response = None
            return InteractionEnvelope(
                surface_kind=TargetKind.WEB,
                success=False,
                summary=f"{intent.upper()} {path}",
                error=str(exc),
            )

        self.last_response = resp
        status = getattr(resp, "status", None)
        return InteractionEnvelope(
            surface_kind=TargetKind.WEB,
            success=True,
            summary=f"{intent.upper()} {path} → {status}",
            artifacts={"status": str(status)} if status is not None else {},
        )


class WebEyes(Eyes):
    """Browser-driven observation. BrowserEngine import is lazy — environments
    without Playwright (CI on Linux without browsers) still construct cleanly,
    failing only on `start()`.
    """

    def __init__(self, target: Target) -> None:
        self._target = target
        self._browser: Any | None = None
        self._page: Any | None = None

    async def start(self) -> None:
        if self._browser is not None:
            return
        try:
            from vxis.interaction.eyes import BrowserEngine  # type: ignore
        except Exception as exc:  # Playwright optional
            raise RuntimeError(f"WebEyes unavailable: {exc}") from exc
        self._browser = BrowserEngine()
        await self._browser.start()
        self._page = await self._browser.new_page()

    async def stop(self) -> None:
        if self._browser is not None:
            try:
                await self._browser.stop()
            finally:
                self._browser = None
                self._page = None

    async def observe(self, focus: str, **kw: object) -> InteractionEnvelope:
        if self._page is None:
            await self.start()
        try:
            assert self._page is not None
            if focus == "screenshot":
                path = str(kw.get("path", "screenshot.png"))
                await self._page.screenshot(path=path)
                return InteractionEnvelope(
                    surface_kind=TargetKind.WEB,
                    success=True,
                    summary=f"screenshot saved: {path}",
                    artifacts={"screenshot": path},
                )
            if focus == "dom":
                html = await self._page.content()
                return InteractionEnvelope(
                    surface_kind=TargetKind.WEB,
                    success=True,
                    summary=f"DOM captured ({len(html)} bytes)",
                    artifacts={"dom_bytes": str(len(html))},
                )
            return InteractionEnvelope(
                surface_kind=TargetKind.WEB,
                success=False,
                summary=f"unknown focus: {focus}",
                error=f"WebEyes.observe focus '{focus}' not implemented",
            )
        except Exception as exc:
            return InteractionEnvelope(
                surface_kind=TargetKind.WEB,
                success=False,
                summary=f"observe {focus}",
                error=str(exc),
            )


class WebXRay(XRay):
    """Passive HTTP interception via mitmproxy + FlowAnalyzer."""

    def __init__(self, target: Target, proxy_port: int = 8080) -> None:
        self._target = target
        self._proxy_port = proxy_port
        self._mitm: Any | None = None
        self._analyzer: Any | None = None

    async def start(self) -> None:
        from vxis.interaction.xray import FlowAnalyzer, MitmProxyManager

        self._analyzer = FlowAnalyzer()
        if MitmProxyManager.is_available():
            self._mitm = MitmProxyManager(port=self._proxy_port)
            try:
                await self._mitm.start()
            except Exception as exc:
                logger.warning("WebXRay mitm start failed: %s", exc)
                self._mitm = None

    async def stop(self) -> None:
        if self._mitm is not None:
            try:
                await self._mitm.stop()
            finally:
                self._mitm = None

    async def capture(self, window: str, **kw: object) -> InteractionEnvelope:
        if self._analyzer is None:
            await self.start()
        assert self._analyzer is not None
        summary = self._analyzer.get_summary()
        return InteractionEnvelope(
            surface_kind=TargetKind.WEB,
            success=True,
            summary=f"capture window={window}: {summary.total_flows} flows",
            artifacts={
                "total_flows": str(summary.total_flows),
                "passive_vulns": str(len(summary.vulnerabilities)),
            },
        )


class WebRecon(Recon):
    """Static-ish recon via SessionManager initial probe → endpoints + tech_stack."""

    def __init__(self, target: Target) -> None:
        self._target = target
        self._mgr = SessionManager()

    async def fingerprint(self, target: Target) -> ReconReport:
        session = await self._mgr.get_session(target.entry)
        try:
            await session.get("/")
        except Exception as exc:
            logger.warning("WebRecon initial probe failed for %s: %s", target.entry, exc)

        fp = session.get_fingerprint() or {}
        tech_list: list[str] = list(fp.get("tech_stack", []) or [])
        endpoints = list(fp.get("endpoints", []) or [])

        components: list[dict[str, str]] = []
        for ep in endpoints:
            components.append({"type": "endpoint", "value": str(ep)})
        for tech in tech_list:
            components.append({"type": "tech", "value": str(tech)})
        if fp.get("waf_detected"):
            components.append({"type": "waf", "value": "detected"})
        if fp.get("has_csrf"):
            components.append({"type": "csrf", "value": "present"})

        host = urlparse(target.entry).netloc or target.entry
        return ReconReport(
            surface_kind=TargetKind.WEB,
            fingerprint={
                "host": host,
                "tech_stack": ",".join(tech_list),
                "endpoints_discovered": str(fp.get("endpoints_discovered", len(endpoints))),
                "waf_detected": str(bool(fp.get("waf_detected"))),
            },
            components=components,
        )


__all__ = ["WebHands", "WebEyes", "WebXRay", "WebRecon"]
