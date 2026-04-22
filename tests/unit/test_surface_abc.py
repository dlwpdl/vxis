"""Surface ABC tests — phase-A.

Verifies TargetKind discriminator + Hands/Eyes/XRay/Recon ABCs + Surface aggregate.
"""
from __future__ import annotations

import pytest


def test_target_kind_enum_values():
    """phase-A.1 — TargetKind covers all 4 surfaces with stable string values."""
    from vxis.interaction.surface import TargetKind

    assert {k.value for k in TargetKind} == {"web", "desktop", "mobile", "game"}
    assert TargetKind.WEB.value == "web"
    assert TargetKind.DESKTOP.value == "desktop"
    assert TargetKind.MOBILE.value == "mobile"
    assert TargetKind.GAME.value == "game"


@pytest.mark.parametrize("cls_name", ["Hands", "Eyes", "XRay", "Recon"])
def test_abcs_cannot_instantiate(cls_name):
    """phase-A.2 — every Surface ABC refuses bare instantiation."""
    from vxis.interaction import surface

    cls = getattr(surface, cls_name)
    with pytest.raises(TypeError):
        cls()


def test_surface_aggregate_validates():
    """phase-A.3 — Surface Pydantic model holds Target + 4 concrete role impls."""
    from vxis.interaction.surface import (
        Eyes,
        Hands,
        InteractionEnvelope,
        Recon,
        ReconReport,
        Surface,
        Target,
        TargetKind,
        XRay,
    )

    class _StubH(Hands):
        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        async def request(self, intent: str, **kw: object) -> InteractionEnvelope:
            return InteractionEnvelope(surface_kind=TargetKind.WEB, success=True, summary="")

    class _StubE(Eyes):
        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        async def observe(self, focus: str, **kw: object) -> InteractionEnvelope:
            return InteractionEnvelope(surface_kind=TargetKind.WEB, success=True, summary="")

    class _StubX(XRay):
        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        async def capture(self, window: str, **kw: object) -> InteractionEnvelope:
            return InteractionEnvelope(surface_kind=TargetKind.WEB, success=True, summary="")

    class _StubR(Recon):
        async def fingerprint(self, target: Target) -> ReconReport:
            return ReconReport(surface_kind=TargetKind.WEB, fingerprint={}, components=[])

    target = Target(kind=TargetKind.WEB, entry="http://x")
    surface_obj = Surface(target=target, hands=_StubH(), eyes=_StubE(), xray=_StubX(), recon=_StubR())
    assert surface_obj.target.kind == TargetKind.WEB
    assert isinstance(surface_obj.hands, Hands)


def test_envelope_round_trips():
    """phase-A.3 — InteractionEnvelope is pure-Pydantic, JSON-serializable."""
    from vxis.interaction.surface import InteractionEnvelope, TargetKind

    env = InteractionEnvelope(
        surface_kind=TargetKind.DESKTOP,
        success=True,
        summary="launched proc 1234",
        artifacts={"flow_jsonl": "/tmp/flows.jsonl"},
    )
    assert InteractionEnvelope.model_validate_json(env.model_dump_json()) == env


def test_recon_report_round_trips():
    """phase-A.3 — ReconReport is pure-Pydantic, JSON-serializable."""
    from vxis.interaction.surface import ReconReport, TargetKind

    rep = ReconReport(
        surface_kind=TargetKind.DESKTOP,
        fingerprint={"arch": "x64", "subsystem": "windows_gui"},
        components=[{"type": "import", "value": "user32.dll!CreateFileW"}],
    )
    assert ReconReport.model_validate_json(rep.model_dump_json()) == rep
