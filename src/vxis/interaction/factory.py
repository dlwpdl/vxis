"""SurfaceFactory — dispatch Target.kind (and Target.os for desktop) to the
matching Surface implementation.

WEB is the production dynamic branch. DESKTOP/macOS has native CLI adapters
(otool/codesign/dtrace). MOBILE/GAME are intentionally not wired until real
runtime surfaces exist; do not connect placeholder stubs to production scans.
"""
from __future__ import annotations

from vxis.interaction.code import CodeEyes, CodeHands, CodeRecon, CodeXRay
from vxis.interaction.desktop.dtrace_xray import MacOSXRay
from vxis.interaction.desktop.macos_hands import MacOSHands
from vxis.interaction.desktop.recon_macho import MacOSRecon
from vxis.interaction.hands import SessionManager
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
            raise NotImplementedError(
                "mobile surface is not production-wired; develop it under incubator/ "
                "and promote only after real APK/IPA + device/emulator execution works."
                "|||모바일 서피스는 아직 프로덕 연결 대상이 아닙니다. 실제 APK/IPA와 "
                "디바이스/에뮬레이터 실행이 완성된 뒤 승격하세요."
            )
        if target.kind == TargetKind.GAME:
            raise NotImplementedError(
                "game surface is not production-wired; develop it under incubator/ "
                "and promote only after real protocol/client execution works."
                "|||게임 서피스는 아직 프로덕 연결 대상이 아닙니다. 실제 프로토콜/클라이언트 "
                "실행이 완성된 뒤 승격하세요."
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
