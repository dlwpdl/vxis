import re

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.interaction.surface import TargetKind
from vxis.pipeline.launcher import RuntimeLaunch, prepare_target_runtime
from vxis.pipeline.scan_pipeline_v2 import (
    ScanPipeline,
    _compute_vxis_score,
    _build_finding_from_dict,
    _SimpleScore,
    _make_scan_id,
    _SEV_TO_LEVEL,
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
async def test_scan_pipeline_v2_activates_ghost_for_ghost_target(monkeypatch):
    from vxis.ghost.layer import ghost_layer

    ghost_layer.deactivate()
    monkeypatch.setenv("VXIS_PROXY_POOL", "socks5://127.0.0.1:9050")
    fake_brain = MagicMock()
    pipe = ScanPipeline(
        brain=fake_brain,
        config=SimpleNamespace(proxy_pool=[]),
        auto_approve_injection=True,
        generate_report=False,
    )
    observed: dict[str, object] = {}

    fake_loop_result = {
        "target": "https://example.com",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 1,
    }

    with patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls:
        mock_loop = MagicMock()

        async def _run():
            observed["active_during_run"] = ghost_layer.is_active()
            observed["proxy_pool"] = list(getattr(ghost_layer, "_proxy_pool", []))
            return fake_loop_result

        mock_loop.run = AsyncMock(side_effect=_run)
        mock_loop.state = MagicMock(messages=[])
        mock_loop_cls.return_value = mock_loop

        ctx = await pipe.run(target="ghost://example.com")

    call_kwargs = mock_loop_cls.call_args.kwargs
    assert call_kwargs["target"] == "https://example.com"
    assert ctx.target == "https://example.com"
    assert observed["active_during_run"] is True
    assert observed["proxy_pool"] == ["socks5://127.0.0.1:9050"]
    assert ghost_layer.is_active() is False


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

    fake_brain = MagicMock()
    pipe = ScanPipeline(brain=fake_brain, auto_approve_injection=True)

    fake_loop_result = {
        "target": "http://x",
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 3,
    }

    async def _fake_loop_run():
        await rep.run(
            title="Test SQL Injection",
            severity="high",
            finding_type="sql_injection",
            affected_component="/login",
            description="Classic bypass",
            evidence="POST /login user=admin'--",
            impact="Login bypass may expose privileged data.",
            technical_analysis=(
                "Negative control invalid credentials returned 401; injection payload "
                "returned an authenticated response twice. repeat_count=2"
            ),
            poc_description="Replay invalid credentials, then replay the SQL injection payload twice.",
            poc_script_code=(
                "POST /login HTTP/1.1\n\nuser=bad&password=bad\n\n"
                "HTTP/1.1 401 Unauthorized\n\nnegative control\n\n"
                "POST /login HTTP/1.1\n\nuser=admin'--\n\n"
                "HTTP/1.1 200 OK\nSet-Cookie: session=admin\n\n"
                "repeat_count=2\n"
                "POST /login HTTP/1.1\n\nuser=admin'--\n\n"
                "HTTP/1.1 200 OK\nSet-Cookie: session=admin"
            ),
            remediation_steps="Use parameterized queries for authentication.",
            verifier_verdict="CONFIRMED",
            replay_gate={
                "status": "passed",
                "method": "machine_http_replay",
                "control_status": 401,
                "replay_status": 200,
                "matched_markers": ["Set-Cookie: session=admin"],
            },
            _replay_gate_machine=True,
        )
        return fake_loop_result

    with patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls, patch(
        "vxis.pipeline.scan_pipeline_v2._reset_finding_store"
    ):
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(side_effect=_fake_loop_run)
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


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [TargetKind.MOBILE, TargetKind.GAME])
async def test_prepare_target_runtime_rejects_unwired_future_surfaces(kind):
    with pytest.raises(NotImplementedError, match="not production-wired"):
        await prepare_target_runtime("x", kind)


# ---------------------------------------------------------------------------
# Fix 2 — scan_id uniqueness (second-granularity collision)
# ---------------------------------------------------------------------------


class TestMakeScanId:
    """scan_id must be unique across concurrent calls in the same second."""

    def test_two_scan_ids_differ(self) -> None:
        """Two calls in the same second must produce different scan_ids."""
        id1 = _make_scan_id()
        id2 = _make_scan_id()
        assert id1 != id2

    def test_scan_id_format_has_random_suffix(self) -> None:
        """scan_id format: VXIS-YYYYMMDD-HHMMSS-<hex6>."""
        sid = _make_scan_id()
        assert re.match(r"^VXIS-\d{8}-\d{6}-[0-9a-f]{6}$", sid), f"Bad format: {sid!r}"

    def test_many_scan_ids_are_all_unique(self) -> None:
        ids = [_make_scan_id() for _ in range(50)]
        assert len(set(ids)) == 50, "Collision detected in 50 rapid scan_ids"


# ---------------------------------------------------------------------------
# Fix 3 — _SEV_TO_LEVEL covers "info" explicitly (two incompatible enums)
# ---------------------------------------------------------------------------


class TestSevToLevel:
    """Both "info" (evidence.schema.Severity.INFO.value) and "informational"
    (models.finding.Severity.informational.value) must map to level 0,
    not rely on the dict's default fallback.
    """

    def test_info_maps_to_zero(self) -> None:
        assert _SEV_TO_LEVEL["info"] == 0

    def test_informational_maps_to_zero(self) -> None:
        assert _SEV_TO_LEVEL["informational"] == 0

    def test_critical_maps_to_three(self) -> None:
        assert _SEV_TO_LEVEL["critical"] == 3

    def test_high_maps_to_two(self) -> None:
        assert _SEV_TO_LEVEL["high"] == 2

    def test_medium_maps_to_one(self) -> None:
        assert _SEV_TO_LEVEL["medium"] == 1

    def test_low_maps_to_zero(self) -> None:
        assert _SEV_TO_LEVEL["low"] == 0

    def test_no_silent_default_needed_for_info(self) -> None:
        """The key must exist — we must not rely on dict.get(_, 0) default."""
        assert "info" in _SEV_TO_LEVEL

    def test_informational_finding_roundtrips_without_pydantic_error(self) -> None:
        """A finding with severity 'informational' must build without ValidationError."""
        finding = _build_finding_from_dict(
            {"title": "Info finding", "severity": "informational", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.severity.value == "informational"

    def test_info_finding_roundtrips_without_pydantic_error(self) -> None:
        """A finding with severity 'info' must build without ValidationError."""
        finding = _build_finding_from_dict(
            {"title": "Info finding", "severity": "info", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.severity.value == "informational"


# ---------------------------------------------------------------------------
# Fix 6 — CVSS vector_string must not be hardcoded to 9.8/Critical
# ---------------------------------------------------------------------------

_CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestBuildFindingCVSS:
    """Low/Info findings must NOT carry the 9.8-Critical vector string."""

    def test_low_finding_not_critical_vector(self) -> None:
        finding = _build_finding_from_dict(
            {"title": "Low finding", "severity": "low", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.cvss is not None
        assert finding.cvss.vector_string != _CRITICAL_VECTOR, (
            "LOW finding incorrectly carries the 9.8/Critical CVSS vector"
        )

    def test_informational_finding_not_critical_vector(self) -> None:
        finding = _build_finding_from_dict(
            {"title": "Info finding", "severity": "informational", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.cvss is not None
        assert finding.cvss.vector_string != _CRITICAL_VECTOR, (
            "INFORMATIONAL finding incorrectly carries the 9.8/Critical CVSS vector"
        )

    def test_info_finding_not_critical_vector(self) -> None:
        finding = _build_finding_from_dict(
            {"title": "Info finding", "severity": "info", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.cvss is not None
        assert finding.cvss.vector_string != _CRITICAL_VECTOR, (
            "INFO finding incorrectly carries the 9.8/Critical CVSS vector"
        )

    def test_critical_finding_keeps_high_base_score(self) -> None:
        """Critical findings must retain their high base score."""
        finding = _build_finding_from_dict(
            {"title": "Critical finding", "severity": "critical", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.cvss is not None
        assert finding.cvss.base_score == 9.5

    def test_medium_finding_not_critical_vector(self) -> None:
        finding = _build_finding_from_dict(
            {"title": "Medium finding", "severity": "medium", "description": "d"},
            scan_id="VXIS-TEST",
            target="http://localhost",
        )
        assert finding.cvss is not None
        assert finding.cvss.vector_string != _CRITICAL_VECTOR
