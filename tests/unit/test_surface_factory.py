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


@pytest.mark.parametrize("kind_name", ["DESKTOP", "MOBILE", "GAME"])
def test_factory_raises_for_unimplemented_kinds(kind_name):
    """phase-B.5 — non-web kinds defer to phase-C/H/I and must raise clearly."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    kind = TargetKind[kind_name]
    with pytest.raises(NotImplementedError) as exc:
        SurfaceFactory.build(Target(kind=kind, entry="x"))
    assert kind.value in str(exc.value).lower()
