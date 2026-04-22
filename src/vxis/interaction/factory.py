"""SurfaceFactory — dispatch Target.kind (and Target.os for desktop) to the
matching Surface implementation.

Phase-B wires the WEB branch. DESKTOP/MOBILE/GAME raise NotImplementedError
with a bilingual message until phases C / H / I land their concrete impls.
"""
from __future__ import annotations

from vxis.interaction.hands import SessionManager
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
        if target.kind == TargetKind.DESKTOP:
            raise NotImplementedError(
                "desktop surface impl pending — see phase-C of the universal "
                "pentesting plan.|||데스크톱 서피스 구현 예정 — phase-C 참조."
            )
        if target.kind == TargetKind.MOBILE:
            raise NotImplementedError(
                "mobile surface stub pending — see phase-H.|||"
                "모바일 서피스 스텁 예정 — phase-H 참조."
            )
        if target.kind == TargetKind.GAME:
            raise NotImplementedError(
                "game surface stub pending — see phase-H.|||"
                "게임 서피스 스텁 예정 — phase-H 참조."
            )
        raise NotImplementedError(f"unknown TargetKind: {target.kind!r}")


__all__ = ["SurfaceFactory"]
