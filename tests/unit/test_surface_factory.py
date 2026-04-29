"""SurfaceFactory tests — phase-B.5.

Factory dispatches by Target.kind; web works today, others raise NotImplementedError
(stubs land in phase-H, real impls in phase-C/I).
"""
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


def test_factory_raises_for_desktop_until_phase_c():
    """phase-B.5 / phase-H — DESKTOP construction still raises (impl in phase-C/I).

    MOBILE/GAME used to raise here too, but phase-H landed stub Surface aggregates
    so Brain code can stay surface-agnostic — see test_mobile_game_surface.py.
    """
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    with pytest.raises(NotImplementedError) as exc:
        SurfaceFactory.build(Target(kind=TargetKind.DESKTOP, entry="x"))
    assert "desktop" in str(exc.value).lower()
