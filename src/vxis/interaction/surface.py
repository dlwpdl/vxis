"""Surface ABC layer — universal app pentesting foundation.

Discriminator (`TargetKind`) + four role ABCs (`Hands`, `Eyes`, `XRay`, `Recon`)
let Brain attack web / desktop / mobile / game targets through one contract.
Concrete implementations live in `web_surface.py` (phase-B), `desktop/*` (phase-C+),
`mobile/*` (phase-H), `game/*` (phase-H).

Brain · Director · Phase logic stay surface-agnostic — they program against the ABC,
the SurfaceFactory binds the right impl per `Target.kind` (+ `Target.os` for desktop).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class TargetKind(str, Enum):
    """Surface stack the Brain is attacking. Stable string values for telemetry."""

    WEB = "web"
    DESKTOP = "desktop"
    MOBILE = "mobile"
    GAME = "game"


class Target(BaseModel):
    """What we're attacking. `entry` shape depends on `kind`:
    web → URL · desktop → exe/.app path · mobile → .ipa/.apk path · game → proto://host:port.
    """

    kind: TargetKind
    entry: str
    os: Literal["linux", "windows", "macos", "ios", "android", "any"] = "any"
    hints: dict[str, str] = Field(default_factory=dict)


class InteractionEnvelope(BaseModel):
    """Surface-agnostic action result so Brain doesn't branch on kind."""

    surface_kind: TargetKind
    success: bool
    summary: str
    artifacts: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class ReconReport(BaseModel):
    """Surface-agnostic recon snapshot. `components` items shape:
    `{"type": "endpoint|import|dylib|window|signature|...", "value": "..."}`.
    """

    surface_kind: TargetKind
    fingerprint: dict[str, str]
    components: list[dict[str, str]] = Field(default_factory=list)


class Hands(ABC):
    """Active interaction — Brain's hands. HTTP request / process launch / IPC write / pkt send."""

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def request(self, intent: str, **kw: object) -> InteractionEnvelope: ...


class Eyes(ABC):
    """Observation — Brain's eyes. DOM snapshot / window screenshot / memory read."""

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def observe(self, focus: str, **kw: object) -> InteractionEnvelope: ...


class XRay(ABC):
    """Passive interception — Brain's x-ray. mitmproxy / WinDivert / dtrace / packet sniff."""

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def capture(self, window: str, **kw: object) -> InteractionEnvelope: ...


class Recon(ABC):
    """Static surface mapping — endpoints / PE imports / Mach-O dylibs / APK manifest."""

    @abstractmethod
    async def fingerprint(self, target: Target) -> ReconReport: ...


class Surface(BaseModel):
    """Aggregate handed to Brain. Concrete impls bound by SurfaceFactory."""

    model_config = {"arbitrary_types_allowed": True}

    target: Target
    hands: Hands
    eyes: Eyes
    xray: XRay
    recon: Recon
