import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.pipeline.scan_pipeline_v2 import (
    ScanPipeline,
    _compute_vxis_score,
    _SimpleScore,
)


@pytest.mark.asyncio
async def test_scan_pipeline_v2_instantiates_with_legacy_signature():
    """Constructor signature must match what cli/main.py:590 passes."""
    fake_brain = MagicMock()
    pipe = ScanPipeline(
        brain=fake_brain,
        config=None,
        event_callback=lambda e, d: None,
        injection_approval_callback=None,
        approval_callback=None,
        auto_approve_injection=True,
        report_output_path="reports/test.html",
    )
    assert pipe.brain is fake_brain
    assert pipe._auto_approve_injection is True


@pytest.mark.asyncio
async def test_scan_pipeline_v2_run_delegates_to_scan_agent_loop():
    """run() must instantiate ScanAgentLoop and call loop.run()."""
    fake_brain = MagicMock()
    events: list[tuple[str, dict]] = []

    def on_event(t, d):
        events.append((t, d))

    pipe = ScanPipeline(brain=fake_brain, event_callback=on_event, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://x",
        "completed": True,
        "iterations": 2,
        "findings": [],
        "messages": 4,
    }

    with patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls:
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop.state = MagicMock(target="http://x")
        mock_loop_cls.return_value = mock_loop

        ctx = await pipe.run(target="http://x")

    mock_loop_cls.assert_called_once()
    call_kwargs = mock_loop_cls.call_args.kwargs
    assert call_kwargs["target"] == "http://x"
    assert call_kwargs["brain"] is fake_brain
    mock_loop.run.assert_awaited_once()
    assert ctx.target == "http://x"
    event_types = [e[0] for e in events]
    assert "phase_start" in event_types
    assert "phase_end" in event_types


@pytest.mark.asyncio
async def test_scan_pipeline_v2_copies_findings_from_store_into_ctx():
    """After the loop runs, findings from finding_tools._get_findings() must appear in ctx.findings."""
    from vxis.agent.tools.finding_tools import ReportFindingTool, _reset_for_tests

    _reset_for_tests()
    rep = ReportFindingTool()
    await rep.run(
        title="Test SQL Injection",
        severity="high",
        finding_type="sql_injection",
        affected_component="/login",
        description="Classic bypass",
        evidence="POST /login user=admin'--",
    )

    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://x",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 3,
    }
    with patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls, patch(
        "vxis.pipeline.scan_pipeline_v2._reset_finding_store"
    ):
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop_cls.return_value = mock_loop

        ctx = await pipe.run(target="http://x")

    assert len(ctx.findings) == 1
    assert "SQL Injection" in ctx.findings[0].title
    assert ctx.vxis_score is not None
    assert ctx.vxis_score.total > 0
    assert ctx.vxis_score.grade in ("A", "B", "C", "D")


def test_compute_vxis_score_severity_weights():
    """Simple score ramps up with higher severity findings."""
    ctx = MagicMock()
    ctx.findings = []
    s, g = _compute_vxis_score(ctx)
    assert s == 0.0 and g == "F"

    f_critical = MagicMock()
    f_critical.severity.value = "critical"
    ctx.findings = [f_critical]
    s1, _ = _compute_vxis_score(ctx)
    assert s1 == 200.0

    f_high = MagicMock()
    f_high.severity.value = "high"
    ctx.findings = [f_high]
    s2, _ = _compute_vxis_score(ctx)
    assert s2 == 100.0
    assert s1 > s2


@pytest.mark.asyncio
async def test_scan_pipeline_v2_emits_benchmark_line_to_stdout(capsys):
    """VXIS_BENCHMARK line must be printed to stdout for Task 11 grep."""
    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://x",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
    }
    with patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls:
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop_cls.return_value = mock_loop

        await pipe.run(target="http://x")

    captured = capsys.readouterr()
    assert "VXIS_BENCHMARK" in captured.out
    assert "brain_decision_count=" in captured.out
    assert "llm_call_count=" in captured.out
    assert "peak_context_bytes=" in captured.out
    assert "findings_count=" in captured.out


def test_simple_score_has_total_and_grade():
    s = _SimpleScore(total=758.8, grade="A")
    assert s.total == 758.8
    assert s.grade == "A"
