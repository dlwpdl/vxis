import pytest
from vxis.agent.scan_loop import ScanAgentLoop, ScanLoopState
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    _reset_for_tests as _reset_findings,
)

class FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}
    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


@pytest.mark.asyncio
async def test_scan_loop_runs_to_finish(monkeypatch):
    """Brain reports a finding, then completes via finish_scan past min_iters.

    History: assertion was `call_count == 1` before the early-finish guard
    (commit d47fd36) added the `iter < min_iters` rejection, then the Q11
    `0 findings` rejection further raised the bar — finish_scan only
    succeeds when there is at least one finding in the store AND iter has
    cleared min_iters (= max_iters // 2).
    """
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    call_count = {"n": 0}

    async def fake_decide(state):
        call_count["n"] += 1
        # First decision drops a finding so Q11's 0-finding gate clears.
        if call_count["n"] == 1:
            return [("report_finding", {
                "title": "stub finding",
                "severity": "low",
                "finding_type": "test_stub",
                "affected_component": "/x",
                "description": "evidence of nothing — fixture only",
            })]
        return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=10)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()
    assert result["completed"] is True
    # min_iters = min(50, max_iters // 2) = 5; the rejection check uses
    # `iter < min_iters`, so iter 5 is the first acceptance window. Sequence:
    # decide #1=report (iter 1), #2-4=finish_scan rejected at iter 2-4 (iter
    # < 5), #5=finish_scan accepted at iter 5. Total = 5 decisions.
    assert call_count["n"] == 5, (
        f"expected 5 decisions (1 report + 3 min_iters rejections + 1 accept), "
        f"got {call_count['n']}"
    )
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
