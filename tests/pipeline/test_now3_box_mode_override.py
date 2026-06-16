"""NOW-3 #1 — explicit box-mode override resolution.

box_mode was implicit: CODE kind → white, everything else → black. The TUI now
lets the operator choose black / white / grey explicitly as the first wizard
step. _resolve_box_mode is the pure decision the pipeline uses, fail-closed to
black: an explicit "black" wins over kind ("블랙박스는 완전히 블랙박스여야함"),
and any invalid override never escalates to source access.
"""
from vxis.interaction.surface import TargetKind
from vxis.pipeline.scan_pipeline_v2 import _resolve_box_mode


def test_none_derives_black_for_web():
    # legacy: no override → dynamic surfaces stay black-box
    assert _resolve_box_mode(None, TargetKind.WEB) == "black"


def test_none_derives_white_for_code():
    # legacy: no override → a CODE target is white-box
    assert _resolve_box_mode(None, TargetKind.CODE) == "white"


def test_explicit_black_forces_black_even_on_code():
    # "블랙박스는 완전히 블랙박스여야함" — an explicit black choice wins over kind
    assert _resolve_box_mode("black", TargetKind.CODE) == "black"


def test_explicit_white_honored_on_web():
    assert _resolve_box_mode("white", TargetKind.WEB) == "white"


def test_explicit_grey_honored_and_normalized():
    assert _resolve_box_mode("grey", TargetKind.WEB) == "grey"
    assert _resolve_box_mode("gray", TargetKind.WEB) == "grey"  # US spelling
    assert _resolve_box_mode("  WHITE ", TargetKind.WEB) == "white"  # trimmed/lowered


def test_invalid_override_fails_closed_to_black_on_web():
    assert _resolve_box_mode("bogus", TargetKind.WEB) == "black"


def test_invalid_override_fails_closed_to_black_on_code():
    # fail-closed: garbage input must NOT silently grant source access
    assert _resolve_box_mode("bogus", TargetKind.CODE) == "black"
    assert _resolve_box_mode("", TargetKind.CODE) == "black"
