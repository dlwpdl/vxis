"""Box-mode resolution is production fail-closed.

VXIS ships black-box Brain tools today. White/grey CODE tooling is not promoted
into the live loop, so every public override resolves to black rather than
advertising source-aware behavior that is not actually wired.
"""
from vxis.interaction.surface import TargetKind
from vxis.pipeline.scan_pipeline_v2 import _resolve_box_mode


def test_none_derives_black_for_web():
    assert _resolve_box_mode(None, TargetKind.WEB) == "black"


def test_none_derives_black_for_code_until_source_tools_are_wired():
    assert _resolve_box_mode(None, TargetKind.CODE) == "black"


def test_explicit_black_forces_black_even_on_code():
    # "블랙박스는 완전히 블랙박스여야함" — an explicit black choice wins over kind
    assert _resolve_box_mode("black", TargetKind.CODE) == "black"


def test_explicit_white_fails_closed_to_black():
    assert _resolve_box_mode("white", TargetKind.WEB) == "black"
    assert _resolve_box_mode("  WHITE ", TargetKind.CODE) == "black"


def test_explicit_grey_fails_closed_to_black():
    assert _resolve_box_mode("grey", TargetKind.WEB) == "black"
    assert _resolve_box_mode("gray", TargetKind.WEB) == "black"


def test_invalid_override_fails_closed_to_black_on_web():
    assert _resolve_box_mode("bogus", TargetKind.WEB) == "black"


def test_invalid_override_fails_closed_to_black_on_code():
    # fail-closed: garbage input must NOT silently grant source access
    assert _resolve_box_mode("bogus", TargetKind.CODE) == "black"
    assert _resolve_box_mode("", TargetKind.CODE) == "black"
