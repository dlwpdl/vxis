import pytest
from vxis.agent.tool_registry import BrainTool, ToolRegistry, ToolResult

class DummyTool:
    name = "dummy"
    description = "returns echo"
    input_schema = {"type": "object", "properties": {"msg": {"type": "string"}}}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, data={"echo": kwargs["msg"]}, summary=f"echoed {kwargs['msg']}")

@pytest.mark.asyncio
async def test_registry_registers_and_dispatches():
    reg = ToolRegistry()
    reg.register(DummyTool())
    assert "dummy" in reg.list_tools()
    result = await reg.dispatch("dummy", {"msg": "hi"})
    assert result.ok is True
    assert result.data == {"echo": "hi"}

@pytest.mark.asyncio
async def test_registry_unknown_tool_returns_error_result():
    reg = ToolRegistry()
    result = await reg.dispatch("ghost", {})
    assert result.ok is False
    assert "unknown tool" in result.summary.lower()
