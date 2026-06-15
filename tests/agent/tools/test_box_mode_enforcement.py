"""NOW-2/2b — black-box hard-enforcement.

A black-box scan must PROVABLY register ZERO interaction.code-backed (source-aware)
Brain tools — the user's directive "블랙박스는 완전히 블랙박스여야함". No code-surface
Brain tools exist yet, so this locks the invariant structurally: the moment a future
change wires source-aware tools, they cannot leak into a black-box scan, and these
tests fail if they do. Fail-closed default = black.
"""
from vxis.agent.tools import build_default_registry


def _tool_instances(reg):
    return list(reg._tools.values())


def test_default_box_mode_is_black_fail_closed():
    # Omitting box_mode == black == no source access.
    assert set(build_default_registry().list_tools()) == set(
        build_default_registry(box_mode="black").list_tools()
    )


def test_blackbox_registers_no_code_surface_tools():
    reg = build_default_registry(box_mode="black")
    leaked = [
        type(t).__name__
        for t in _tool_instances(reg)
        if type(t).__module__.startswith("vxis.interaction.code")
    ]
    assert leaked == [], f"black-box scan leaked source-aware tools: {leaked}"


def test_white_box_is_superset_of_black():
    black = set(build_default_registry(box_mode="black").list_tools())
    white = set(build_default_registry(box_mode="white").list_tools())
    assert white >= black
