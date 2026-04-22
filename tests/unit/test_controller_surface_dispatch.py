"""InteractionController × Surface dispatch — phase-B.6.

The controller now routes API_CALL intents through `surface.hands.request(...)`
so kind-aware dispatch (web/desktop/mobile/game) can land in later phases. This
keeps the existing public ctor signature and rich InteractionResult
(forms/links/error_patterns) intact: the WEB surface shares the controller's
SessionManager so cookies / CSRF / auth state stay coherent and there is no
double request.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_analyzed_response_stub(status: int = 200, body: str = "<html></html>") -> MagicMock:
    """Build a duck-typed AnalyzedResponse the controller can consume."""
    resp = MagicMock()
    resp.status = status
    resp.text = body
    resp.headers = {"content-type": "text/html"}
    resp.url = "http://x/"
    resp.is_error = status >= 400
    resp.forms = []
    resp.links = []
    resp.error_patterns = []
    resp.response = MagicMock()
    resp.response.request = MagicMock(method="GET", url="http://x/", headers={})
    return resp


@pytest.mark.asyncio
async def test_controller_dispatches_api_call_via_surface_hands() -> None:
    """phase-B.6 — execute(API_CALL) routes through WebHands.request."""
    from vxis.interaction.controller import (
        InteractionAction,
        InteractionController,
        InteractionIntent,
    )
    from vxis.interaction.surface import InteractionEnvelope, TargetKind
    from vxis.interaction.web_surface import WebHands

    captured: list[tuple[str, dict[str, object]]] = []

    async def fake_request(self: WebHands, intent: str, **kw: object) -> InteractionEnvelope:
        captured.append((intent, kw))
        self.last_response = _make_analyzed_response_stub()
        return InteractionEnvelope(
            surface_kind=TargetKind.WEB,
            success=True,
            summary=f"{intent} hit",
            artifacts={"status": "200"},
        )

    with patch.object(WebHands, "request", new=fake_request), \
         patch.object(WebHands, "start", new=AsyncMock(return_value=None)), \
         patch.object(WebHands, "stop", new=AsyncMock(return_value=None)):
        ctrl = InteractionController(target="http://x", enable_eyes=False, enable_xray=False)
        # Bypass the live network probe — start() calls _initial_probe.
        with patch.object(ctrl, "_initial_probe", new=AsyncMock(return_value=None)):
            await ctrl.start()
            try:
                result = await ctrl.execute(
                    InteractionAction(intent=InteractionIntent.API_CALL, url="/")
                )
            finally:
                await ctrl.stop()

    assert captured, "WebHands.request was never invoked"
    intent, kw = captured[0]
    assert intent.upper() == "GET"
    assert kw.get("path") == "/"
    assert result.success is True
    assert result.status_code == 200


@pytest.mark.asyncio
async def test_controller_accepts_injected_surface() -> None:
    """phase-B.6 — Surface injected at construction time is honoured (no auto-build)."""
    from vxis.interaction.controller import InteractionController
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    injected = SurfaceFactory.build(Target(kind=TargetKind.WEB, entry="http://injected"))
    ctrl = InteractionController(target="http://x", surface=injected)
    assert ctrl._surface is injected
