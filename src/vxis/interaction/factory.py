"""SurfaceFactory — dispatch Target.kind (and Target.os for desktop) to the
matching Surface implementation.

Phase-B wires the WEB branch. Phase-H wires MOBILE/GAME stubs (construction
succeeds; method calls raise bilingual NotImplementedError so Brain detects
the gap explicitly). Phase-I wires DESKTOP/macOS via the native CLI
adapters (otool/codesign/dtrace). DESKTOP/Windows still raises until
phase-C lands; DESKTOP/Linux is explicitly out-of-scope per the plan.
"""
from __future__ import annotations

from vxis.interaction.code import CodeEyes, CodeHands, CodeRecon, CodeXRay
from vxis.interaction.desktop.dtrace_xray import MacOSXRay
from vxis.interaction.desktop.macos_hands import MacOSHands
from vxis.interaction.desktop.recon_macho import MacOSRecon
from vxis.interaction.game.game_surface import GameEyes, GameHands, GameRecon, GameXRay
from vxis.interaction.hands import SessionManager
from vxis.interaction.mobile.mobile_surface import (
    MobileEyes,
    MobileHands,
    MobileRecon,
    MobileXRay,
)
from vxis.interaction.surface import (
    Eyes,
    InteractionEnvelope,
    Surface,
    Target,
    TargetKind,
)
from vxis.interaction.web_surface import WebEyes, WebHands, WebRecon, WebXRay


class _NoopEyes(Eyes):
    """Placeholder Eyes for surfaces without a UI capture impl yet.

    macOS desktop in phase-I exposes Hands (subprocess) + XRay (dtrace) +
    Recon (otool/codesign), but visual UI capture would need pyobjc /
    accessibility APIs that we haven't shipped yet. Instead of letting Brain
    crash mid-loop on `eyes.observe(...)`, we surface an explicit
    `success=False` envelope so it can fall back gracefully.
    """

    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def observe(self, focus: str, **kw: object) -> InteractionEnvelope:
        return InteractionEnvelope(
            surface_kind=self._target.kind,
            success=False,
            summary=f"eyes unavailable on this surface (focus={focus})",
            error="visual capture not implemented for this surface yet",
        )


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
            return SurfaceFactory._build_desktop(target)
        if target.kind == TargetKind.CODE:
            # CODE surface is hypothesis-only: Hands=file I/O, Eyes=AST,
            # XRay=git history, Recon=manifest detection.
            # report_finding MUST NOT be called from any Code* impl.
            return Surface(
                target=target,
                hands=CodeHands(target),
                eyes=CodeEyes(target),
                xray=CodeXRay(target),
                recon=CodeRecon(target),
            )
        raise NotImplementedError(f"unknown TargetKind: {target.kind!r}")

    @staticmethod
    def _build_desktop(target: Target) -> Surface:
        """Branch on `target.os` for the DESKTOP kind.

        macOS  → phase-I MacOS* impls (otool/codesign/dtrace native CLI)
        Windows → phase-C pending (SCFW pre-approval needed for pywin32/frida)
        Linux  → out-of-scope per the universal pentesting plan
        """
        os_name = (target.os or "").lower()
        if os_name == "macos":
            return Surface(
                target=target,
                hands=MacOSHands(target),
                eyes=_NoopEyes(target),
                xray=MacOSXRay(target),
                recon=MacOSRecon(),
            )
        if os_name == "windows":
            raise NotImplementedError(
                "desktop/windows surface pending — see phase-C of the universal "
                "pentesting plan (SCFW pre-approval required for pywin32 / frida)."
                "|||데스크톱/윈도우 서피스 구현 예정 — phase-C 참조 (SCFW 승인 필요)."
            )
        if os_name == "linux":
            raise NotImplementedError(
                "desktop/linux out-of-scope for this plan — phase-linux-impl-pending."
                "|||데스크톱/리눅스 본 플랜 범위 밖 — phase-linux-impl-pending."
            )
        raise NotImplementedError(
            f"desktop/{target.os!r} unmapped — supported: macos (windows/linux pending)"
        )


__all__ = ["SurfaceFactory"]
