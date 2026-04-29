"""GameSurface stubs — phase-H.

GameHands / GameEyes / GameXRay raise bilingual NotImplementedError pending
the full game-pentest pipeline (memory_scanner / anti_cheat_detector /
economy_tester / protocol_analyzer in src/vxis/plugins/game/ already exist
but they're plugin-shaped, not Surface-shaped — wiring is a future plan).

GameRecon does a partial delegate today: it parses target.entry as a
proto://host:port URL and emits one component per discovered field. No
live capture, but Brain still gets structured fingerprint material so the
chain reasoning can proceed instead of hitting an opaque NotImplementedError.
"""
from __future__ import annotations

from urllib.parse import urlparse

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
    "GameHands not implemented — packet send / RPC call bridge pending.|||"
    "게임 Hands 미구현 — 패킷 전송 / RPC 호출 브리지 연결 예정."
)
_STUB_MSG_EYES = (
    "GameEyes not implemented — frame grab / memory scan pending.|||"
    "게임 Eyes 미구현 — 프레임 캡처 / 메모리 스캔 연결 예정."
)
_STUB_MSG_XRAY = (
    "GameXRay not implemented — packet capture / replay pending.|||"
    "게임 X-Ray 미구현 — 패킷 캡처 / 재전송 연결 예정."
)


class GameHands(Hands):
    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        raise NotImplementedError(_STUB_MSG_HANDS)

    async def stop(self) -> None:
        return None

    async def request(self, intent: str, **kw: object) -> InteractionEnvelope:
        raise NotImplementedError(_STUB_MSG_HANDS)


class GameEyes(Eyes):
    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        raise NotImplementedError(_STUB_MSG_EYES)

    async def stop(self) -> None:
        return None

    async def observe(self, focus: str, **kw: object) -> InteractionEnvelope:
        raise NotImplementedError(_STUB_MSG_EYES)


class GameXRay(XRay):
    def __init__(self, target: Target) -> None:
        self._target = target

    async def start(self) -> None:
        raise NotImplementedError(_STUB_MSG_XRAY)

    async def stop(self) -> None:
        return None

    async def capture(self, window: str, **kw: object) -> InteractionEnvelope:
        raise NotImplementedError(_STUB_MSG_XRAY)


class GameRecon(Recon):
    """Partial delegate — parses entry URL into protocol/host/port components."""

    def __init__(self, target: Target) -> None:
        self._target = target

    async def fingerprint(self, target: Target) -> ReconReport:
        entry = target.entry or ""
        parsed = urlparse(entry)

        components: list[dict[str, str]] = []
        fingerprint: dict[str, str] = {"entry": entry}

        scheme = (parsed.scheme or "").strip()
        host = (parsed.hostname or "").strip()
        port = parsed.port

        if scheme:
            components.append({"type": "protocol", "value": scheme})
            fingerprint["protocol"] = scheme
        if host:
            components.append({"type": "host", "value": host})
            fingerprint["host"] = host
        if port is not None:
            components.append({"type": "port", "value": str(port)})
            fingerprint["port"] = str(port)

        # No-scheme entries (e.g. "192.168.1.1:6666") still parse usefully via
        # netloc fallback so Brain gets at least one structured component.
        if not host and ":" in entry and "://" not in entry:
            host_part, _, port_part = entry.partition(":")
            if host_part:
                components.append({"type": "host", "value": host_part})
                fingerprint["host"] = host_part
            if port_part.isdigit():
                components.append({"type": "port", "value": port_part})
                fingerprint["port"] = port_part

        return ReconReport(
            surface_kind=TargetKind.GAME,
            fingerprint=fingerprint,
            components=components,
        )


__all__ = ["GameHands", "GameEyes", "GameXRay", "GameRecon"]
