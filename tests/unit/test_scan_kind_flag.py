"""CLI `--kind` flag thread-through — phase-A.6.

Verifies the new `--kind` Typer option lands on `pipeline.run(...)` so the
desktop / mobile / game phases (B+) can dispatch by `Target.kind`.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner


def _stub_preflight() -> object:
    return type(
        "PF",
        (),
        {
            "target_reachable": True,
            "target_latency_ms": 1.0,
            "brain_ready": True,
            "brain_backend": "stub",
            "docker_available": True,
            "github_token": True,
            "proxy_pool_size": 0,
            "warnings": [],
            "errors": [],
            "can_scan": True,
        },
    )()


def _stub_ctx() -> object:
    return type(
        "FakeCtx",
        (),
        {
            "findings": [],
            "scan_id": "VXIS-fake",
            "duration_seconds": 0.1,
            "vxis_score": None,
            "peak_context_bytes": 0,
            "target": "x",
        },
    )()


def test_kind_flag_threads_through_to_pipeline_run():
    """phase-A.6 — `vxis scan ... --kind desktop` calls pipeline.run(kind=DESKTOP)."""
    from vxis.cli.main import app
    from vxis.interaction.surface import TargetKind

    fake_pipeline = MagicMock()
    fake_pipeline.run = AsyncMock(return_value=_stub_ctx())

    with (
        patch("vxis.cli.preflight.run_preflight", return_value=_stub_preflight()),
        patch("vxis.pipeline.scan_pipeline_v2.ScanPipeline", return_value=fake_pipeline),
        patch("vxis.agent.brain.AgentBrain"),
    ):
        runner = CliRunner()
        result = runner.invoke(app, ["scan", "http://x", "--kind", "desktop"])

    assert result.exit_code == 0, result.output
    _, kwargs = fake_pipeline.run.call_args
    assert kwargs["kind"] == TargetKind.DESKTOP


def test_kind_flag_default_is_web():
    """phase-A.6 — omitting --kind defaults to TargetKind.WEB (back-compat)."""
    from vxis.cli.main import app
    from vxis.interaction.surface import TargetKind

    fake_pipeline = MagicMock()
    fake_pipeline.run = AsyncMock(return_value=_stub_ctx())

    with (
        patch("vxis.cli.preflight.run_preflight", return_value=_stub_preflight()),
        patch("vxis.pipeline.scan_pipeline_v2.ScanPipeline", return_value=fake_pipeline),
        patch("vxis.agent.brain.AgentBrain"),
    ):
        runner = CliRunner()
        result = runner.invoke(app, ["scan", "http://x"])

    assert result.exit_code == 0, result.output
    _, kwargs = fake_pipeline.run.call_args
    assert kwargs["kind"] == TargetKind.WEB
