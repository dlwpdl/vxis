"""NOW-2/2b — black-box hard-enforcement.

A black-box scan must PROVABLY register ZERO interaction.code-backed (source-aware)
Brain tools — the user's directive "블랙박스는 완전히 블랙박스여야함". No code-surface
Brain tools exist yet, so this locks the invariant structurally: the moment a future
change wires source-aware tools, they cannot leak into a black-box scan, and these
tests fail if they do. Fail-closed default = black.
"""
import pytest

from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools import _enforce_box_mode, build_default_registry


def _tool_instances(reg):
    return list(reg._tools.values())


class _FakeSourceAwareTool:
    # __module__ is THIS test module, not vxis.interaction.code — proves the
    # metadata guard (F5) catches source access regardless of module path.
    name = "read_repo_file"
    description = "x"
    input_schema = {"type": "object"}
    source_access = True

    async def run(self, **kwargs):  # pragma: no cover
        return None


class _NormalTool:
    name = "http_request"
    description = "x"
    input_schema = {"type": "object"}

    async def run(self, **kwargs):  # pragma: no cover
        return None


def test_tool_is_source_aware_reads_metadata():
    assert ToolRegistry.tool_is_source_aware(_FakeSourceAwareTool()) is True
    assert ToolRegistry.tool_is_source_aware(_NormalTool()) is False  # absent attr → False


def test_enforce_box_mode_raises_on_source_aware_in_blackbox():
    reg = ToolRegistry()
    reg.register(_FakeSourceAwareTool())
    with pytest.raises(RuntimeError):
        _enforce_box_mode(reg, "black")
    # white / grey may carry source-aware tools
    _enforce_box_mode(reg, "white")
    _enforce_box_mode(reg, "grey")


def test_default_registry_has_no_metadata_source_aware_tools():
    reg = build_default_registry(box_mode="black")
    assert [t.name for t in _tool_instances(reg) if ToolRegistry.tool_is_source_aware(t)] == []


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
