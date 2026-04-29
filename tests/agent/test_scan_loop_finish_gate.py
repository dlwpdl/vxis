"""Phase Q11 — finish_scan must reject when there are zero findings.

Q10 smoke regression: Calculator.app went from 21 findings (Q9) to 0 findings
(Q10) because Brain happened to call finish_scan at iter 25/50 with nothing
reported yet. Pre-Q11 the rejection ladder was:

    iter < min_iters       → reject (line 1098)
    findings ≥ 3, chains < → reject (line 1128)
    else                   → completed = True; break

The middle branch is gated on `findings ≥ 3`, so 0-finding finish_scan past
min_iters fell straight through to acceptance. This test pins the closed gap:
zero-finding finish_scan is always rejected.
"""
from __future__ import annotations

import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import _reset_for_tests as _reset_findings


class _FinishTool:
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
async def test_finish_scan_rejected_when_zero_findings_past_min_iters() -> None:
    """With 0 findings, finish_scan must be rejected even past min_iters.

    Drives Brain to spam finish_scan; with max_iters=10 the only way the loop
    completes is via finish_scan acceptance. Q11 must force the loop to run
    out the clock instead.
    """
    reg = ToolRegistry()
    reg.register(_FinishTool())

    loop = ScanAgentLoop(target="http://x", registry=reg, max_iters=10)

    async def always_finish(state):
        return [("finish_scan", {})]

    loop._decide = always_finish  # type: ignore[assignment]
    result = await loop.run()

    assert result["completed"] is False, (
        "finish_scan with 0 findings must be rejected past min_iters; "
        "scan must NOT silently complete with empty report."
    )
    assert result["iterations"] == 10, (
        f"loop must run to max_iters when finish_scan is gated on findings; "
        f"got iterations={result['iterations']}"
    )
