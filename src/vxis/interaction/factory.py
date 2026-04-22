"""SurfaceFactory — dispatch Target.kind (and Target.os for desktop) to the
matching Surface implementation.

Phase-B wires the WEB branch. Phase-H wires MOBILE/GAME stubs (construction
succeeds; method calls raise bilingual NotImplementedError so Brain detects
the gap explicitly). DESKTOP still raises until phase-C (Windows) / phase-I
(macOS) land their concrete impls.
"""
from __future__ import annotations

from vxis.interaction.game.game_surface import GameEyes, GameHands, GameRecon, GameXRay
from vxis.interaction.hands import SessionManager
from vxis.interaction.mobile.mobile_surface import (
    MobileEyes,
    MobileHands,
    MobileRecon,
    MobileXRay,
)
from vxis.interaction.surface import Surface, Target, TargetKind
from vxis.interaction.web_surface import WebEyes, WebHands, WebRecon, WebXRay


class SurfaceFactory:
    """Build a Surface aggregate for a given Target.

    `session_mgr` lets the caller share a SessionManager between the surface
    and other in-process clients (the InteractionController in particular)
    so cookies, CSRF tokens, and auth state stay coherent.
    """

    @staticmethod
    def build(target: Target, *, session_mgr: SessionManager | None = None) -> Surface:
        if target.kind == TargetKind.WEB:
            return Surface(
                target=target,
                hands=WebHands(target, session_mgr=session_mgr),
                eyes=WebEyes(target),
                xray=WebXRay(target),
                recon=WebRecon(target),
            )
        if target.kind == TargetKind.MOBILE:
            return Surface(
                target=target,
                hands=MobileHands(target),
                eyes=MobileEyes(target),
                xray=MobileXRay(target),
                recon=MobileRecon(target),
            )
        if target.kind == TargetKind.GAME:
            return Surface(
                target=target,
                hands=GameHands(target),
                eyes=GameEyes(target),
                xray=GameXRay(target),
                recon=GameRecon(target),
            )
        if target.kind == TargetKind.DESKTOP:
            raise NotImplementedError(
                "desktop surface impl pending — see phase-C of the universal "
                "pentesting plan.|||데스크톱 서피스 구현 예정 — phase-C 참조."
            )
        raise NotImplementedError(f"unknown TargetKind: {target.kind!r}")


__all__ = ["SurfaceFactory"]
