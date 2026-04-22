"""MobileSurface stubs — phase-H.

Construction is cheap and never raises; every behavioural method raises a
bilingual NotImplementedError so Brain (and any future scan loop branching
on Surface) can detect the gap with a precise message instead of a cryptic
AttributeError.

The real impl will wrap frida-mobile / objection / MobSF static analysis /
drozer dynamic exploit modules in a follow-up plan. Until then,
InteractionController catches these errors and emits an informational
finding (see _execute_http) so the observation stream stays coherent.
"""
from __future__ import annotations

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

_STUB_MSG_HANDS = (
    "MobileHands not implemented — frida-mobile/objection bridge pending.|||"
    "모바일 Hands 미구현 — frida-mobile/objection 브리지 연결 예정."
)
_STUB_MSG_EYES = (
    "MobileEyes not implemented — Appium/UIAutomator screen capture pending.|||"
    "모바일 Eyes 미구현 — Appium/UIAutomator 화면 캡처 연결 예정."
)
_STUB_MSG_XRAY = (
    "MobileXRay not implemented — burp/mitm + ssl-pinning bypass pending.|||"
    "모바일 X-Ray 미구현 — burp/mitm + SSL 핀 우회 연결 예정."
)
_STUB_MSG_RECON = (
    "MobileRecon not implemented — APK/IPA static unpack + manifest pending.|||"
    "모바일 Recon 미구현 — APK/IPA 정적 언팩 + manifest 연결 예정."
)


class MobileHands(Hands):
    """Stub — accepts construction, fails on any real interaction."""

    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        raise NotImplementedError(_STUB_MSG_HANDS)

    async def stop(self) -> None:
        # idempotent no-op so controller cleanup paths don't double-raise
        return None

    async def request(self, intent: str, **kw: object) -> InteractionEnvelope:
        raise NotImplementedError(_STUB_MSG_HANDS)


class MobileEyes(Eyes):
    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        raise NotImplementedError(_STUB_MSG_EYES)

    async def stop(self) -> None:
        return None

    async def observe(self, focus: str, **kw: object) -> InteractionEnvelope:
        raise NotImplementedError(_STUB_MSG_EYES)


class MobileXRay(XRay):
    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        raise NotImplementedError(_STUB_MSG_XRAY)

    async def stop(self) -> None:
        return None

    async def capture(self, window: str, **kw: object) -> InteractionEnvelope:
        raise NotImplementedError(_STUB_MSG_XRAY)


class MobileRecon(Recon):
    def __init__(self, target: Target) -> None:
        self._target = target

    async def fingerprint(self, target: Target) -> ReconReport:
        raise NotImplementedError(_STUB_MSG_RECON)


# Discriminator marker so cross_protocol synthesizer can fall back to MOBILE
# even when an evidence's agent_id is not in _AGENT_LAYER_MAP.
SURFACE_KIND = TargetKind.MOBILE


__all__ = ["MobileHands", "MobileEyes", "MobileXRay", "MobileRecon", "SURFACE_KIND"]
