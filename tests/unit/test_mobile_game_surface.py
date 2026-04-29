"""Mobile + Game surface stubs — phase-H.

After this phase the SurfaceFactory MUST construct a Surface aggregate for
every TargetKind value (web/desktop/mobile/game). DESKTOP still raises on
construction (real impl lands in phase-C/I); MOBILE and GAME construct cleanly
but raise bilingual NotImplementedError on every method except GameRecon,
which delivers a minimal fingerprint parsed from the entry URL.

The InteractionController catches the NotImplementedError surfaced by an
unsupported surface and emits an informational `InteractionFinding` so Brain
keeps a coherent observation stream instead of bubbling a raw exception.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


# ── H.1 — factory builds Surface for every kind ─────────────────────────────


def test_factory_builds_surface_for_mobile():
    """phase-H.1 — TargetKind.MOBILE must construct a Surface stub (no raise)."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.mobile.mobile_surface import (
        MobileEyes,
        MobileHands,
        MobileRecon,
        MobileXRay,
    )
    from vxis.interaction.surface import Surface, Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.MOBILE, entry="/tmp/app.ipa"))
    assert isinstance(s, Surface)
    assert isinstance(s.hands, MobileHands)
    assert isinstance(s.eyes, MobileEyes)
    assert isinstance(s.xray, MobileXRay)
    assert isinstance(s.recon, MobileRecon)


def test_factory_builds_surface_for_game():
    """phase-H.1 — TargetKind.GAME must construct a Surface stub (no raise)."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.game.game_surface import (
        GameEyes,
        GameHands,
        GameRecon,
        GameXRay,
    )
    from vxis.interaction.surface import Surface, Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.GAME, entry="game://srv:12345"))
    assert isinstance(s, Surface)
    assert isinstance(s.hands, GameHands)
    assert isinstance(s.eyes, GameEyes)
    assert isinstance(s.xray, GameXRay)
    assert isinstance(s.recon, GameRecon)


def test_factory_resolves_every_target_kind():
    """phase-H.1 — every TargetKind value must be reachable through the factory.

    DESKTOP still raises (phase-C/I land later); WEB/MOBILE/GAME all return a
    Surface aggregate so Brain code can stay surface-agnostic.
    """
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Surface, Target, TargetKind

    for kind in TargetKind:
        if kind == TargetKind.DESKTOP:
            with pytest.raises(NotImplementedError):
                SurfaceFactory.build(Target(kind=kind, entry="x"))
            continue
        s = SurfaceFactory.build(Target(kind=kind, entry="x"))
        assert isinstance(s, Surface)
        assert s.target.kind == kind


# ── H.2 — stub methods raise bilingual NotImplementedError ──────────────────


@pytest.mark.asyncio
async def test_mobile_hands_request_raises_bilingual_not_implemented():
    """phase-H.2 — MobileHands.request raises with both EN and KO messaging."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.MOBILE, entry="x"))
    with pytest.raises(NotImplementedError) as exc:
        await s.hands.request("anything")
    msg = str(exc.value)
    assert "|||" in msg, "bilingual marker missing"
    assert "mobile" in msg.lower()


@pytest.mark.asyncio
async def test_mobile_eyes_observe_raises_bilingual_not_implemented():
    """phase-H.2 — MobileEyes.observe must surface bilingual stub message."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.MOBILE, entry="x"))
    with pytest.raises(NotImplementedError) as exc:
        await s.eyes.observe("dom")
    assert "|||" in str(exc.value)
    assert "모바일" in str(exc.value)  # Korean half present


@pytest.mark.asyncio
async def test_mobile_xray_capture_raises_bilingual_not_implemented():
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.MOBILE, entry="x"))
    with pytest.raises(NotImplementedError) as exc:
        await s.xray.capture("network")
    assert "|||" in str(exc.value)


@pytest.mark.asyncio
async def test_mobile_recon_fingerprint_raises_bilingual_not_implemented():
    """phase-H.2 — MobileRecon raises (no static path yet, unlike GameRecon)."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.MOBILE, entry="x"))
    with pytest.raises(NotImplementedError) as exc:
        await s.recon.fingerprint(s.target)
    assert "|||" in str(exc.value)


@pytest.mark.asyncio
async def test_game_hands_request_raises_bilingual_not_implemented():
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.GAME, entry="game://x:1"))
    with pytest.raises(NotImplementedError) as exc:
        await s.hands.request("send_packet")
    msg = str(exc.value)
    assert "|||" in msg
    assert "game" in msg.lower() or "게임" in msg


@pytest.mark.asyncio
async def test_game_eyes_observe_raises_bilingual_not_implemented():
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.GAME, entry="game://x:1"))
    with pytest.raises(NotImplementedError) as exc:
        await s.eyes.observe("frame")
    assert "|||" in str(exc.value)


@pytest.mark.asyncio
async def test_game_xray_capture_raises_bilingual_not_implemented():
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.GAME, entry="game://x:1"))
    with pytest.raises(NotImplementedError) as exc:
        await s.xray.capture("packets")
    assert "|||" in str(exc.value)


# ── H.3 — GameRecon partial delegate ────────────────────────────────────────


@pytest.mark.asyncio
async def test_game_recon_partial_delegate_emits_components_from_entry():
    """phase-H.3 — GameRecon.fingerprint extracts protocol/host/port from entry URL.

    No live packet capture (that's a future game-pipeline phase). What we MUST
    deliver today: the entry URL parses into structured components so Brain has
    something concrete to reason about, and the surface_kind is correctly tagged.
    """
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(
        Target(kind=TargetKind.GAME, entry="tcp://game.example.com:54321")
    )
    report = await s.recon.fingerprint(s.target)
    assert report.surface_kind == TargetKind.GAME
    assert len(report.components) >= 1
    # at minimum a host or port component
    types = {c["type"] for c in report.components}
    assert types & {"host", "port", "protocol"}


@pytest.mark.asyncio
async def test_game_recon_handles_unparseable_entry():
    """phase-H.3 — junk entry must still produce a ReconReport, not raise."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    s = SurfaceFactory.build(Target(kind=TargetKind.GAME, entry="junk-no-scheme"))
    report = await s.recon.fingerprint(s.target)
    assert report.surface_kind == TargetKind.GAME
    # at least the raw entry is preserved for Brain to inspect
    assert report.fingerprint.get("entry") == "junk-no-scheme"


# ── H.4 — controller emits informational finding for unsupported surface ────


@pytest.mark.asyncio
async def test_controller_unsupported_surface_emits_informational_finding():
    """phase-H.4 — execute() catches stub NotImplementedError and emits
    an informational InteractionFinding so the Brain stream stays coherent.
    """
    from vxis.interaction.controller import (
        InteractionAction,
        InteractionController,
        InteractionIntent,
    )
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    injected = SurfaceFactory.build(Target(kind=TargetKind.MOBILE, entry="x"))
    ctrl = InteractionController(
        target="x", surface=injected, enable_eyes=False, enable_xray=False
    )
    with patch.object(ctrl, "_initial_probe", new=AsyncMock(return_value=None)):
        await ctrl.start()
        try:
            result = await ctrl.execute(
                InteractionAction(intent=InteractionIntent.API_CALL, url="/")
            )
        finally:
            await ctrl.stop()

    assert result.findings, "expected at least one InteractionFinding"
    assert any(
        f.severity == "informational" and "surface_unsupported" in f.title.lower()
        for f in result.findings
    )


@pytest.mark.asyncio
async def test_controller_unsupported_surface_finding_carries_kind():
    """phase-H.4 — informational finding records which surface_kind is unsupported
    so Brain knows the gap is mobile vs game vs desktop."""
    from vxis.interaction.controller import (
        InteractionAction,
        InteractionController,
        InteractionIntent,
    )
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    injected = SurfaceFactory.build(Target(kind=TargetKind.GAME, entry="game://x:1"))
    ctrl = InteractionController(
        target="x", surface=injected, enable_eyes=False, enable_xray=False
    )
    with patch.object(ctrl, "_initial_probe", new=AsyncMock(return_value=None)):
        await ctrl.start()
        try:
            result = await ctrl.execute(
                InteractionAction(intent=InteractionIntent.API_CALL, url="/")
            )
        finally:
            await ctrl.stop()

    matched = [
        f for f in result.findings
        if "surface_unsupported" in f.title.lower() and f.surface == "game"
    ]
    assert matched, "expected surface=game to be tagged on the informational finding"
