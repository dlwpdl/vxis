"""SurfaceFactory tests for production-wired surfaces."""
from __future__ import annotations

import pytest


def test_factory_builds_web_surface():
    """phase-B.5 — TargetKind.WEB resolves to a Surface aggregate of Web* impls."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Surface, Target, TargetKind
    from vxis.interaction.web_surface import WebEyes, WebHands, WebRecon, WebXRay

    s = SurfaceFactory.build(Target(kind=TargetKind.WEB, entry="http://x"))
    assert isinstance(s, Surface)
    assert isinstance(s.hands, WebHands)
    assert isinstance(s.eyes, WebEyes)
    assert isinstance(s.xray, WebXRay)
    assert isinstance(s.recon, WebRecon)


def test_factory_raises_for_desktop_without_supported_os():
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    with pytest.raises(NotImplementedError) as exc:
        SurfaceFactory.build(Target(kind=TargetKind.DESKTOP, entry="x"))
    assert "desktop" in str(exc.value).lower()


@pytest.mark.parametrize("kind", ["mobile", "game"])
def test_factory_rejects_unwired_future_surfaces(kind: str):
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    with pytest.raises(NotImplementedError) as exc:
        SurfaceFactory.build(Target(kind=TargetKind(kind), entry="x"))

    assert "not production-wired" in str(exc.value)
