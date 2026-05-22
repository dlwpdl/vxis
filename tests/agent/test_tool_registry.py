import pytest
from vxis.agent.tool_registry import ToolRegistry, ToolResult

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


class RequiredTool:
    name = "required"
    description = "requires msg"
    input_schema = {
        "type": "object",
        "properties": {"msg": {"type": "string"}},
        "required": ["msg"],
    }

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, data={"msg": kwargs["msg"]}, summary="ok")


@pytest.mark.asyncio
async def test_registry_rejects_non_object_args():
    reg = ToolRegistry()
    reg.register(RequiredTool())
    result = await reg.dispatch("required", "bad")  # type: ignore[arg-type]
    assert result.ok is False
    assert result.error == "invalid_args"
    assert "must be an object" in result.summary


@pytest.mark.asyncio
async def test_registry_rejects_missing_required_arg():
    reg = ToolRegistry()
    reg.register(RequiredTool())
    result = await reg.dispatch("required", {})
    assert result.ok is False
    assert result.error == "invalid_args"
    assert "missing required arg: msg" in result.summary


class LenientTool:
    name = "lenient"
    description = "accepts local model scalar variants"
    input_schema = {
        "type": "object",
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST"]},
            "seconds": {"type": "number"},
        },
        "required": ["method", "seconds"],
    }

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, data=kwargs, summary="ok")


@pytest.mark.asyncio
async def test_registry_allows_case_variants_and_numeric_strings():
    reg = ToolRegistry()
    reg.register(LenientTool())
    result = await reg.dispatch("lenient", {"method": "get", "seconds": "2"})
    assert result.ok is True
    assert result.data == {"method": "get", "seconds": "2"}


class CleanupTool:
    name = "cleanup"
    description = "owns resources"
    input_schema = {"type": "object", "properties": {}}

    def __init__(self) -> None:
        self.cleaned = False

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True)

    async def cleanup(self) -> None:
        self.cleaned = True


@pytest.mark.asyncio
async def test_registry_cleanup_calls_tool_cleanup_hooks():
    reg = ToolRegistry()
    tool = CleanupTool()
    reg.register(tool)
    await reg.cleanup()
    assert tool.cleaned is True


def test_registry_get_tool_returns_registered_instance():
    reg = ToolRegistry()
    tool = DummyTool()
    reg.register(tool)
    assert reg.get_tool("dummy") is tool
    assert reg.get_tool("missing") is None
