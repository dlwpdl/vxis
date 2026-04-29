import pytest
from vxis.agent.scan_loop import ScanAgentLoop
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


@pytest.mark.asyncio
async def test_finish_scan_rejected_when_two_findings_have_no_chain():
    """Two findings are enough to require at least one crown-jewel chain."""
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "first finding",
            "severity": "medium",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "debug endpoint exposed",
        })],
        [("report_finding", {
            "title": "second finding",
            "severity": "high",
            "finding_type": "auth_bypass",
            "affected_component": "/login",
            "description": "auth bypass evidence",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=8)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert result["completed"] is False
    chain_rejections = [
        m for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and (m["content"].get("result") or {}).get("data", {}).get("needs_chains")
    ]
    assert chain_rejections, "finish_scan must be rejected until the two findings are chained"


@pytest.mark.asyncio
async def test_vector_candidates_record_attempt_outcomes_for_brain_tools():
    reg = ToolRegistry()
    reg.register(FinishTool())

    class ShellTool:
        name = "shell_exec"
        description = "shell"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(
                ok=True,
                summary="sqlmap confirmed SQL injection",
                data={"stdout": "parameter q is vulnerable"},
            )

    reg.register(ShellTool())

    decisions = iter([
        [("shell_exec", {"command": "sqlmap -u http://localhost:3000/rest/products/search?q=test --batch"})],
        [("finish_scan", {})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    outcomes = result["attempt_outcomes"]
    assert any(o["candidate_id"] == "web:sqli" and o["status"] == "found" for o in outcomes)
    candidates = {c["id"]: c for c in result["vector_candidates"]}
    assert candidates["web:sqli"]["attempts"] >= 1
    assert candidates["web:sqli"]["status"] == "found"


@pytest.mark.asyncio
async def test_finish_scan_rejected_when_high_priority_candidates_unattempted():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "one finding",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "debug endpoint exposed",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert result["completed"] is False
    candidate_rejections = [
        m for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and (m["content"].get("result") or {}).get("data", {}).get("unresolved_vector_candidates")
    ]
    assert candidate_rejections
