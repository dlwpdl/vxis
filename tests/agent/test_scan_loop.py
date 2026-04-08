import pytest
from vxis.agent.scan_loop import ScanAgentLoop, ScanLoopState
from vxis.agent.tool_registry import ToolRegistry, ToolResult

class FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}
    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})

@pytest.mark.asyncio
async def test_scan_loop_runs_to_finish(monkeypatch):
    reg = ToolRegistry()
    reg.register(FinishTool())

    call_count = {"n": 0}
    async def fake_decide(state):
        call_count["n"] += 1
        return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=10)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()
    assert result["completed"] is True
    assert call_count["n"] == 1
    assert len(loop.state.messages) >= 2  # system + user + tool result

@pytest.mark.asyncio
async def test_scan_loop_respects_max_iters():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=3)
    async def never_finish(state):
        return [("nonexistent_tool", {})]
    loop._decide = never_finish  # type: ignore
    result = await loop.run()
    assert result["completed"] is False
    assert loop.state.iteration == 3
