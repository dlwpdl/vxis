"""ScanContext.kind tests — phase-A.4 + A.5.

Verifies the new `kind: TargetKind` field replaces the legacy `target_type` str
while keeping a backward-compat property shim, and that ScoreTracker is wired
from `kind.value` (not the literal "web").
"""
from __future__ import annotations


def test_context_default_kind_is_web():
    """phase-A.4 — default kind is WEB; target_type shim returns "web"."""
    from vxis.interaction.surface import TargetKind
    from vxis.pipeline.context import ScanContext

    ctx = ScanContext(target="http://x")
    assert ctx.kind == TargetKind.WEB
    assert ctx.target_type == "web"  # backward-compat shim


def test_context_kind_propagates_to_score_tracker():
    """phase-A.5 — explicit kind=DESKTOP wires ScoreTracker(target_type="desktop")."""
    from vxis.interaction.surface import TargetKind
    from vxis.pipeline.context import ScanContext

    ctx = ScanContext(target="C:/x.exe", kind=TargetKind.DESKTOP)
    assert ctx.kind == TargetKind.DESKTOP
    assert ctx.target_type == "desktop"
    assert ctx.score_tracker.target_type == "desktop"


def test_context_checkpoint_emits_target_type_string(tmp_path):
    """phase-A.4 — save_checkpoint still serializes target_type as a string."""
    import json

    from vxis.interaction.surface import TargetKind
    from vxis.pipeline.context import ScanContext

    ctx = ScanContext(target="x", kind=TargetKind.GAME, scan_id="VXIS-test")
    out = ctx.save_checkpoint(tmp_path / "ckpt.json")
    payload = json.loads(out.read_text())
    assert payload["target_type"] == "game"
