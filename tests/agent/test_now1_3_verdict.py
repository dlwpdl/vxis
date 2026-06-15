"""NOW-1/1.3a — verifier verdict writeback onto the persisted finding.

Flow: _verify_and_gate stamps the proceed-bound args dict with the verdict ->
ReportFindingTool persists verifier_verdict/verified onto the finding dict (both
the new-finding literal and the dedup-merge branch, UPGRADE-ONLY).
"""
import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    _get_findings,
    _reset_for_tests as _reset_findings,
)


class _VerifyStub:
    name = "verify_finding"
    description = "verify"
    input_schema = {"type": "object"}

    def __init__(self, verdict: str) -> None:
        self.verdict = verdict

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(
            ok=True,
            summary=f"verify_finding: {self.verdict}",
            data={"verdict": self.verdict, "confidence": "medium", "reasoning": "stub reason"},
        )


def _args(severity: str = "medium") -> dict:
    return {
        "title": "Reflected XSS",
        "severity": severity,
        "finding_type": "xss",
        "affected_component": "/search",
        "description": "d",
        "impact": "i",
        "technical_analysis": "t",
        "poc_description": "p",
        "poc_script_code": "c",
        "evidence": "e",
    }


def _med(component: str, **extra) -> dict:
    base = dict(
        title="Reflected XSS",
        severity="medium",
        finding_type="xss",
        affected_component=component,
        description="d",
        evidence="e",
    )
    base.update(extra)
    return base


@pytest.fixture(autouse=True)
def _isolate():
    _reset_findings()
    yield
    _reset_findings()


def _loop(verdict: str) -> ScanAgentLoop:
    reg = ToolRegistry()
    reg.register(_VerifyStub(verdict))
    return ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)


# ── _verify_and_gate stamps the proceed-bound args dict ──────────────────────
@pytest.mark.asyncio
async def test_verify_and_gate_stamps_args_on_proceed():
    loop = _loop("CONFIRMED")
    args = _args("medium")
    assert await loop._verify_and_gate(args, require_confirmed=False) is None
    assert args["verifier_verdict"] == "CONFIRMED"
    assert "verifier_confidence" in args
    assert "verifier_reasoning" in args


@pytest.mark.asyncio
async def test_verify_and_gate_stamps_unconfirmed():
    loop = _loop("UNCONFIRMED")
    args = _args("medium")
    assert await loop._verify_and_gate(args, require_confirmed=False) is None
    assert args["verifier_verdict"] == "UNCONFIRMED"


@pytest.mark.asyncio
async def test_verify_and_gate_skip_leaves_args_unstamped():
    # informational is below the gate severity set → returns None without stamping.
    loop = _loop("REFUTED")
    args = _args("informational")
    assert await loop._verify_and_gate(args, require_confirmed=False) is None
    assert "verifier_verdict" not in args


# ── ReportFindingTool persists verdict onto the finding ──────────────────────
@pytest.mark.asyncio
async def test_report_finding_stamps_confirmed():
    await ReportFindingTool().run(
        **_med("/a"), verifier_verdict="CONFIRMED", verifier_confidence="high", verifier_reasoning="proof"
    )
    f = _get_findings()[0]
    assert f["verifier_verdict"] == "CONFIRMED"
    assert f["verified"] is True


@pytest.mark.asyncio
async def test_report_finding_unconfirmed_not_verified():
    await ReportFindingTool().run(**_med("/b"), verifier_verdict="UNCONFIRMED")
    f = _get_findings()[0]
    assert f["verifier_verdict"] == "UNCONFIRMED"
    assert f["verified"] is False


@pytest.mark.asyncio
async def test_report_finding_absent_verdict_blank_not_verified():
    # No verifier_verdict (info / no-verifier / legacy) → blank, kept, not verified.
    await ReportFindingTool().run(**_med("/c"))
    f = _get_findings()[0]
    assert f["verifier_verdict"] == ""
    assert f["verified"] is False


@pytest.mark.asyncio
async def test_dedup_promotes_unconfirmed_to_confirmed():
    tool = ReportFindingTool()
    await tool.run(**_med("/dup"), verifier_verdict="UNCONFIRMED")
    r2 = await tool.run(**_med("/dup", title="variant"), verifier_verdict="CONFIRMED")
    assert (r2.data or {}).get("deduped") is True
    f = _get_findings()[0]
    assert f["verifier_verdict"] == "CONFIRMED"
    assert f["verified"] is True


@pytest.mark.asyncio
async def test_dedup_never_downgrades_confirmed():
    tool = ReportFindingTool()
    await tool.run(**_med("/dup2"), verifier_verdict="CONFIRMED")
    await tool.run(**_med("/dup2", title="variant"), verifier_verdict="UNCONFIRMED")
    f = _get_findings()[0]
    assert f["verifier_verdict"] == "CONFIRMED"
    assert f["verified"] is True
