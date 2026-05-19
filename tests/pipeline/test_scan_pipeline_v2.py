import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.interaction.surface import TargetKind
from vxis.pipeline.launcher import RuntimeLaunch, prepare_target_runtime
from vxis.pipeline.scan_pipeline_v2 import (
    ScanPipeline,
    _compute_vxis_score,
    _build_finding_from_dict,
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
async def test_scan_pipeline_v2_uses_platform_launcher_runtime():
    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "/resolved/App.app",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
        "shared_notes": ["launcher seeded note"],
    }

    runtime = RuntimeLaunch(
        kind=TargetKind.DESKTOP,
        original_target="~/App.app",
        resolved_target="/resolved/App.app",
        launcher_name="desktop_local",
        runtime_mode="local_process",
        metadata={"entrypoint": "/resolved/App.app"},
        shared_notes=["launcher:desktop prepared"],
    )

    with patch("vxis.pipeline.scan_pipeline_v2.prepare_target_runtime", new=AsyncMock(return_value=runtime)), patch(
        "vxis.pipeline.scan_pipeline_v2.ScanAgentLoop"
    ) as mock_loop_cls:
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop_cls.return_value = mock_loop

        ctx = await pipe.run(target="~/App.app", kind=TargetKind.DESKTOP)

    call_kwargs = mock_loop_cls.call_args.kwargs
    assert call_kwargs["target"] == "/resolved/App.app"
    assert call_kwargs["target_kind"] == TargetKind.DESKTOP
    assert ctx.target == "/resolved/App.app"
    assert ctx.runtime_profile["launcher_name"] == "desktop_local"
    assert "desktop prepared" in " ".join(ctx.launcher_notes)
    assert ctx.target_hints == {}


@pytest.mark.asyncio
async def test_scan_pipeline_v2_seeds_loop_from_target_memory():
    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://localhost:3000",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
        "review_history": [],
        "branches": [],
    }

    runtime = RuntimeLaunch(
        kind=TargetKind.WEB,
        original_target="http://localhost:3000",
        resolved_target="http://localhost:3000",
        launcher_name="web_docker_aware",
        runtime_mode="docker_local_target",
        metadata={"entrypoint": "http://localhost:3000"},
        shared_notes=["launcher:web target looks local/containerized"],
    )

    fake_state = MagicMock()
    with patch("vxis.pipeline.scan_pipeline_v2.prepare_target_runtime", new=AsyncMock(return_value=runtime)), patch(
        "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
        return_value={
            "target_known": True,
            "prior_scan_count": 2,
            "known_findings": [
                {
                    "finding_type": "sql_injection",
                    "affected_component": "/rest/products/search?q=",
                    "title": "SQL injection on q",
                }
            ],
            "successful_tactics": [
                {"finding_type": "sql_injection", "reasoning": "Confirmed with transcript"}
            ],
            "refuted_patterns": [
                {"finding_type": "error_oracle", "affected_component": "/api/foo"}
            ],
            "branch_leads": [
                {
                    "id": "branch-1",
                    "vector_id": "WEB-SQLI-001",
                    "title": "Dump product table",
                    "role": "post_exploit_worker",
                    "phase": "data_access",
                    "objective": "Extract rows",
                    "next_step": "Run sqlmap --dump",
                }
            ],
        },
    ), patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls:
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop.state = fake_state
        mock_loop_cls.return_value = mock_loop

        ctx = await pipe.run(target="http://localhost:3000", kind=TargetKind.WEB)

    assert ctx.target_memory["target_known"] is True
    assert fake_state.ensure_vector_candidate.called
    assert fake_state.ensure_branch.called
    assert fake_state.add_shared_note.call_count >= 3
    shared_note_blob = " ".join(str(call.args[0]) for call in fake_state.add_shared_note.call_args_list)
    assert "memory strategy:" in shared_note_blob
    assert "memory refuted:" in shared_note_blob
    branch_call = fake_state.ensure_branch.call_args
    assert branch_call.kwargs["owner"] == "memory"
    assert branch_call.kwargs["blocker"] == "carry-over lead"


@pytest.mark.asyncio
async def test_scan_pipeline_v2_dedups_carryover_review_titles():
    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://localhost:3000",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
        "review_history": [],
        "branches": [],
    }

    runtime = RuntimeLaunch(
        kind=TargetKind.WEB,
        original_target="http://localhost:3000",
        resolved_target="http://localhost:3000",
        launcher_name="web_docker_aware",
        runtime_mode="docker_local_target",
        metadata={},
        shared_notes=[],
    )

    fake_state = MagicMock()
    with patch("vxis.pipeline.scan_pipeline_v2.prepare_target_runtime", new=AsyncMock(return_value=runtime)), patch(
        "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
        return_value={"target_known": False, "prior_scan_count": 0, "known_findings": []},
    ), patch("vxis.growth.scan_retrospective.load_latest_target_retrospective", return_value={
        "improvement_hints": [],
        "review_queue": [
            {"id": "a", "status": "open", "title": "needs_chains", "affected_component": "http://localhost:3000"},
            {"id": "b", "status": "open", "title": "carryover:needs_chains", "affected_component": "http://localhost:3000"},
            {"id": "c", "status": "open", "title": "needs_chains", "affected_component": "http://localhost:3000"},
        ],
    }), patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls:
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop.state = fake_state
        mock_loop_cls.return_value = mock_loop

        await pipe.run(target="http://localhost:3000", kind=TargetKind.WEB)

    assert fake_state.record_review_item.call_count == 1


@pytest.mark.asyncio
async def test_scan_pipeline_v2_skips_broken_magicmock_carryover_items():
    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://localhost:3000",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
        "review_history": [],
        "branches": [],
    }

    runtime = RuntimeLaunch(
        kind=TargetKind.WEB,
        original_target="http://localhost:3000",
        resolved_target="http://localhost:3000",
        launcher_name="web_docker_aware",
        runtime_mode="docker_local_target",
        metadata={},
        shared_notes=[],
    )

    fake_state = MagicMock()
    with patch("vxis.pipeline.scan_pipeline_v2.prepare_target_runtime", new=AsyncMock(return_value=runtime)), patch(
        "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
        return_value={"target_known": False, "prior_scan_count": 0, "known_findings": []},
    ), patch("vxis.growth.scan_retrospective.load_latest_target_retrospective", return_value={
        "improvement_hints": [],
        "review_queue": [
            {"id": "a", "status": "open", "title": "needs_chains", "affected_component": "http://localhost:3000", "reason": "normal"},
            {"id": "b", "status": "open", "title": "sqli", "affected_component": "http://localhost:3000", "reason": "<MagicMock name='mock'>"},
        ],
    }), patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls:
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop.state = fake_state
        mock_loop_cls.return_value = mock_loop

        await pipe.run(target="http://localhost:3000", kind=TargetKind.WEB)

    assert fake_state.record_review_item.call_count == 1


@pytest.mark.asyncio
async def test_scan_pipeline_v2_exposes_aggregated_findings_after_recording():
    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://localhost:3000",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
        "review_history": [],
        "branches": [],
    }

    runtime = RuntimeLaunch(
        kind=TargetKind.WEB,
        original_target="http://localhost:3000",
        resolved_target="http://localhost:3000",
        launcher_name="web_docker_aware",
        runtime_mode="docker_local_target",
        metadata={},
        shared_notes=[],
    )

    with patch("vxis.pipeline.scan_pipeline_v2.prepare_target_runtime", new=AsyncMock(return_value=runtime)), patch(
        "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
        side_effect=[
            {"target_known": False, "prior_scan_count": 0, "known_findings": []},
            {
                "target_known": True,
                "prior_scan_count": 2,
                "known_findings": [{"finding_type": "sql_injection", "affected_component": "/rest/products/search"}],
                "aggregated_findings": [{"finding_type": "sql_injection", "affected_component": "/rest/products/search", "title": "SQL injection on q", "severity": "critical", "occurrences": 2}],
            },
        ],
    ), patch("vxis.pipeline.scan_pipeline_v2._record_scan_memory") as mock_record, patch(
        "vxis.pipeline.scan_pipeline_v2.ScanAgentLoop"
    ) as mock_loop_cls, patch(
        "vxis.pipeline.scan_pipeline_v2._get_finding_dicts",
        return_value=[{
            "id": "VXIS-0001",
            "title": "SQL injection on q",
            "severity": "critical",
            "finding_type": "sql_injection",
            "affected_component": "/rest/products/search",
            "description": "confirmed",
            "impact": "db access",
            "technical_analysis": "confirmed",
            "poc_description": "replay",
            "poc_script_code": "GET /rest/products/search?q='",
            "remediation_steps": "parameterize",
        }],
    ):
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=fake_loop_result)
        mock_loop.state = MagicMock(target="http://localhost:3000", messages=[])
        mock_loop_cls.return_value = mock_loop

        ctx = await pipe.run(target="http://localhost:3000", kind=TargetKind.WEB)

    mock_record.assert_called_once()
    assert len(ctx.aggregated_findings) == 1
    assert ctx.aggregated_findings[0]["occurrences"] == 2


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
        impact="Login bypass may expose privileged data.",
        technical_analysis="The login endpoint accepted an injection payload and returned an authenticated response.",
        poc_description="Replay the same POST request with the SQL injection payload.",
        poc_script_code="POST /login user=admin'--",
        remediation_steps="Use parameterized queries for authentication.",
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


def test_build_finding_from_dict_preserves_extra_evidence():
    finding = _build_finding_from_dict(
        {
            "id": "VXIS-9000",
            "title": "SSRF on url",
            "severity": "high",
            "finding_type": "ssrf",
            "affected_component": "http://localhost:3000/api/proxy",
            "description": "Server-side fetch observed",
            "impact": "Internal reachability",
            "technical_analysis": "Baseline and payload diverged",
            "poc_description": "Replay payload",
            "poc_script_code": "GET /api/proxy?url=http://127.0.0.1",
            "extra_evidence": [
                {
                    "evidence_type": "callback",
                    "title": "Internal Reachability",
                    "content": "Signal: localhost banner",
                },
                {
                    "evidence_type": "retrieval",
                    "title": "Retrieved Internal Data",
                    "content": "Sample: root:x:0:0",
                },
            ],
        },
        "scan-1",
        "http://localhost:3000",
    )
    evidence_types = [ev.evidence_type for ev in finding.evidence]
    assert evidence_types == ["exploit", "callback", "retrieval"]


@pytest.mark.asyncio
async def test_prepare_target_runtime_normalizes_desktop_path(tmp_path):
    app_dir = tmp_path / "Demo.app"
    app_dir.mkdir()
    runtime = await prepare_target_runtime(str(app_dir), TargetKind.DESKTOP)
    assert runtime.resolved_target == str(app_dir.resolve())
    assert runtime.launcher_name == "desktop_local"
    assert runtime.runtime_mode == "local_process"
    assert runtime.metadata["path_exists"] is True


@pytest.mark.asyncio
async def test_prepare_target_runtime_marks_local_web_target_as_docker_aware():
    runtime = await prepare_target_runtime(
        "http://localhost:3000",
        TargetKind.WEB,
        hints={"compose_file": "infra/benchmarks/juice-shop.yml", "service": "juice-shop"},
    )
    assert runtime.launcher_name == "web_docker_aware"
    assert runtime.runtime_mode == "docker_local_target"
    assert runtime.metadata["local_target"] is True
    assert runtime.metadata["compose_file"] == "infra/benchmarks/juice-shop.yml"
