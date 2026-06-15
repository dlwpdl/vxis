"""NOW-1 / 1.1 — single verifier chokepoint `_verify_and_gate`.

These pin the behaviour the two drifted gate copies must share once consolidated:
- scan_loop_run.py inline auto-verify (Brain direct report_finding): UNCONFIRMED passes
  (require_confirmed=False) and may spawn a gap branch; REFUTED blocks.
- scan_loop_actions._dispatch_report_finding_checked (skill/auto): require_confirmed=True
  blocks non-CONFIRMED; REFUTED blocks.

1.1 is behaviour-preserving: verification still fires only on high/critical here; the
all-severity change is 1.2.
"""
import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import _reset_for_tests as _reset_findings


class _VerifyStub:
    name = "verify_finding"
    description = "verify"
    input_schema = {"type": "object"}

    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        self.calls: list[dict] = []

    async def run(self, **kwargs) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(
            ok=True,
            summary=f"verify_finding: {self.verdict}",
            data={"verdict": self.verdict, "confidence": "medium", "reasoning": "stub reason"},
        )


def _args(severity: str = "high") -> dict:
    return {
        "title": "SQL injection",
        "severity": severity,
        "finding_type": "sqli",
        "affected_component": "/api/products",
        "description": "d",
        "impact": "i",
        "technical_analysis": "t",
        "poc_description": "p",
        "poc_script_code": "c",
        "evidence": "e",
    }


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


def _loop(verdict: str) -> tuple[ScanAgentLoop, _VerifyStub]:
    reg = ToolRegistry()
    stub = _VerifyStub(verdict)
    reg.register(stub)
    return ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3), stub


@pytest.mark.asyncio
async def test_confirmed_high_passes():
    loop, stub = _loop("CONFIRMED")
    result = await loop._verify_and_gate(_args("high"), require_confirmed=True)
    assert result is None  # None = proceed to report
    assert len(stub.calls) == 1
    assert loop.state.verdict_counts.get("CONFIRMED") == 1


@pytest.mark.asyncio
async def test_refuted_high_blocks():
    loop, _ = _loop("REFUTED")
    result = await loop._verify_and_gate(_args("high"), require_confirmed=True)
    assert isinstance(result, ToolResult)
    assert result.ok is False
    assert result.error == "verifier_blocked"
    assert (result.data or {}).get("verdict") == "REFUTED"


@pytest.mark.asyncio
async def test_unconfirmed_blocks_when_require_confirmed():
    loop, _ = _loop("UNCONFIRMED")
    result = await loop._verify_and_gate(_args("high"), require_confirmed=True)
    assert isinstance(result, ToolResult)
    assert result.ok is False
    assert result.error == "verifier_blocked"


@pytest.mark.asyncio
async def test_unconfirmed_passes_when_not_require_confirmed():
    # scan_loop_run.py (Brain-direct) semantics: UNCONFIRMED proceeds.
    loop, _ = _loop("UNCONFIRMED")
    result = await loop._verify_and_gate(_args("high"), require_confirmed=False)
    assert result is None


@pytest.mark.asyncio
async def test_medium_severity_is_verified():
    # 1.2: medium/low are now verified too (was skipped in 1.1).
    loop, stub = _loop("CONFIRMED")
    result = await loop._verify_and_gate(_args("medium"), require_confirmed=True)
    assert result is None  # CONFIRMED proceeds
    assert len(stub.calls) == 1  # verifier WAS invoked for medium
    assert loop.state.verdict_counts.get("CONFIRMED") == 1


@pytest.mark.asyncio
async def test_refuted_medium_blocks():
    loop, _ = _loop("REFUTED")
    result = await loop._verify_and_gate(_args("medium"), require_confirmed=True)
    assert isinstance(result, ToolResult)
    assert result.ok is False
    assert result.error == "verifier_blocked"


@pytest.mark.asyncio
async def test_unconfirmed_medium_proceeds_even_with_require_confirmed():
    # 1.2 guards against over-suppression: UNCONFIRMED medium/low is NOT blocked
    # (verdict-writeback + report exclusion is 1.3). Only high/critical block on
    # UNCONFIRMED here.
    loop, _ = _loop("UNCONFIRMED")
    result = await loop._verify_and_gate(_args("medium"), require_confirmed=True)
    assert result is None


@pytest.mark.asyncio
async def test_informational_severity_skips_verification():
    loop, stub = _loop("REFUTED")
    result = await loop._verify_and_gate(_args("informational"), require_confirmed=True)
    assert result is None
    assert stub.calls == []  # informational is not a reportable-gate severity


@pytest.mark.asyncio
async def test_no_verify_tool_passes():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    result = await loop._verify_and_gate(_args("critical"), require_confirmed=True)
    assert result is None
