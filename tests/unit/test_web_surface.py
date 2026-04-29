"""WebSurface tests — phase-B.

Wraps SessionManager/BrowserEngine/MitmProxyManager as Hands/Eyes/XRay/Recon
without behavior change for `--kind web`.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_web_surface_classes_implement_abcs():
    """phase-B.1 — every WebSurface concrete class implements its ABC."""
    from vxis.interaction.surface import Eyes, Hands, Recon, Target, TargetKind, XRay
    from vxis.interaction.web_surface import WebEyes, WebHands, WebRecon, WebXRay

    target = Target(kind=TargetKind.WEB, entry="http://x")
    assert isinstance(WebHands(target), Hands)
    assert isinstance(WebEyes(target), Eyes)
    assert isinstance(WebXRay(target), XRay)
    assert isinstance(WebRecon(target), Recon)


@pytest.mark.asyncio
async def test_web_hands_request_routes_through_session_manager():
    """phase-B.2 — WebHands.request delegates to SessionManager.get_session."""
    from vxis.interaction.surface import Target, TargetKind
    from vxis.interaction.web_surface import WebHands

    fake_session = MagicMock()
    fake_session.request = AsyncMock(
        return_value=MagicMock(status=200, text="ok", headers={}),
    )

    with patch("vxis.interaction.web_surface.SessionManager") as SM:
        SM.return_value.get_session = AsyncMock(return_value=fake_session)

        h = WebHands(Target(kind=TargetKind.WEB, entry="http://x"))
        await h.start()
        env = await h.request("GET", path="/")

    assert env.success is True
    assert env.surface_kind == TargetKind.WEB
    SM.return_value.get_session.assert_awaited_once()
    fake_session.request.assert_awaited_once()


@pytest.mark.asyncio
async def test_web_recon_emits_recon_report():
    """phase-B.3 — WebRecon.fingerprint returns ReconReport with components."""
    from vxis.interaction.surface import Target, TargetKind
    from vxis.interaction.web_surface import WebRecon

    fake_session = MagicMock()
    fake_session.get = AsyncMock(return_value=MagicMock(status=200))
    fake_session.get_fingerprint = MagicMock(
        return_value={
            "tech_stack": ["nginx", "express"],
            "endpoints_discovered": 3,
            "endpoints": ["/", "/api", "/login"],
            "waf_detected": False,
            "has_csrf": True,
        }
    )

    with patch("vxis.interaction.web_surface.SessionManager") as SM:
        SM.return_value.get_session = AsyncMock(return_value=fake_session)

        r = WebRecon(Target(kind=TargetKind.WEB, entry="http://x"))
        report = await r.fingerprint(r._target)

    assert report.surface_kind == TargetKind.WEB
    assert any(c["type"] == "endpoint" for c in report.components)
    assert any(c["type"] == "tech" and "nginx" in c["value"] for c in report.components)


@pytest.mark.asyncio
async def test_web_hands_request_returns_error_envelope_on_failure():
    """phase-B.2 — WebHands.request wraps exceptions in error envelope, not raises."""
    from vxis.interaction.surface import Target, TargetKind
    from vxis.interaction.web_surface import WebHands

    failing_session = MagicMock()
    failing_session.request = AsyncMock(side_effect=RuntimeError("boom"))

    with patch("vxis.interaction.web_surface.SessionManager") as SM:
        SM.return_value.get_session = AsyncMock(return_value=failing_session)

        h = WebHands(Target(kind=TargetKind.WEB, entry="http://x"))
        await h.start()
        env = await h.request("GET", path="/")

    assert env.success is False
    assert env.error and "boom" in env.error
