import pytest

from vxis.agent.tool_registry import BrainTool, ToolRegistry, ToolResult
from vxis.agent.tools import build_default_registry
from vxis.agent.tools.control_tools import FinishScanTool, ThinkTool, WaitTool


@pytest.mark.asyncio
async def test_finish_scan_tool_returns_ok():
    tool = FinishScanTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "finish_scan"
    result = await tool.run()
    assert result.ok is True
    assert result.data == {
        "final": True,
        "final_report": {
            "executive_summary": "",
            "methodology": "",
            "technical_analysis": "",
            "recommendations": "",
        },
    }
    assert "finished" in result.summary.lower()


@pytest.mark.asyncio
async def test_think_tool_logs_and_returns_ok():
    tool = ThinkTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "think"
    result = await tool.run(thought="I should try the login endpoint next")
    assert result.ok is True
    assert "login endpoint" in result.summary


@pytest.mark.asyncio
async def test_wait_tool_sleeps_and_clamps():
    import time
    tool = WaitTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "wait"
    t0 = time.monotonic()
    result = await tool.run(seconds=0.1)
    elapsed = time.monotonic() - t0
    assert result.ok is True
    assert 0.05 <= elapsed < 1.0


@pytest.mark.asyncio
async def test_wait_tool_clamps_oversized_request():
    import time
    tool = WaitTool()
    t0 = time.monotonic()
    result = await tool.run(seconds=100)
    elapsed = time.monotonic() - t0
    assert result.ok is True
    assert elapsed < 6.0
    assert "waited 5" in result.summary.lower()


def test_build_default_registry_registers_all_three():
    reg = build_default_registry()
    tools = reg.list_tools()
    assert "finish_scan" in tools
    assert "think" in tools
    assert "wait" in tools
    assert len(tools) >= 3  # control tools present; more registered by later tasks


def test_build_default_registry_describe_all_shape_matches_think_in_loop():
    """Sanity: describe_all() output must be list[dict] with name/description/input_schema."""
    reg = build_default_registry()
    catalog = reg.describe_all()
    assert isinstance(catalog, list)
    assert len(catalog) >= 3  # control tools present; more registered by later tasks
    for entry in catalog:
        assert "name" in entry
        assert "description" in entry
        assert "input_schema" in entry
        assert isinstance(entry["name"], str)
        assert isinstance(entry["description"], str)
        assert isinstance(entry["input_schema"], dict)
