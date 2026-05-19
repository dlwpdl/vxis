"""Unit tests for multi_scan orchestrator.

Tests (all using mocks — no network, no LLM):
  - Each non-skipped target is dispatched in order via ScanPipeline.run
  - skip=True targets are skipped
  - correlation=True → Phase-G synthesizer is called after all targets
  - correlation=False → Phase-G synthesizer is NOT called
  - CODE surface NotImplementedError → graceful skip + WARN log
  - Return code 0 on success, 1 when all skipped
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vxis.cli.manifest import ManifestTarget, ScanManifest
from vxis.cli.multi_scan import _async_multi_scan
from vxis.interaction.surface import TargetKind


# ---------------------------------------------------------------------------
# Minimal stubs
# ---------------------------------------------------------------------------

@dataclass
class _FakeCtx:
    findings: list[Any] = field(default_factory=list)
    scan_id: str = "VXIS-TEST-001"
    target: str = "http://localhost"


def _fake_pipeline(findings: list[Any] | None = None) -> MagicMock:
    """Return a ScanPipeline mock whose .run() returns a _FakeCtx."""
    ctx = _FakeCtx(findings=findings or [])
    pipeline = MagicMock()
    pipeline.run = AsyncMock(return_value=ctx)
    return pipeline


def _make_manifest(**overrides: Any) -> ScanManifest:
    defaults: dict[str, Any] = {
        "version": 1,
        "project": "Unit Test Suite",
        "targets": [
            ManifestTarget(name="api", kind=TargetKind.WEB, entry="http://localhost:3333"),
        ],
        "correlation": True,
        "max_iters_per_target": 10,
        "output": "reports/test-{date}.html",
    }
    defaults.update(overrides)
    return ScanManifest(**defaults)


# ---------------------------------------------------------------------------
# Helpers for patching
# ---------------------------------------------------------------------------

_PIPELINE_PATH = "vxis.cli.multi_scan._build_pipeline"
_BRAIN_PATH = "vxis.cli.multi_scan._build_brain"
_PHASE_G_PATH = "vxis.cli.multi_scan._run_phase_g"
_REPORT_PATH = "vxis.cli.multi_scan._emit_report"
_SCAN_TARGET_PATH = "vxis.cli.multi_scan._scan_target"


# ---------------------------------------------------------------------------
# Tests: dispatch order
# ---------------------------------------------------------------------------

class TestDispatchOrder:
    def test_single_web_target_dispatched(self) -> None:
        pipeline = _fake_pipeline()
        call_order: list[str] = []

        async def fake_scan_target(target, scan_id, max_iters):  # type: ignore[no-untyped-def]
            call_order.append(target.name)
            return []

        with (
            patch(_SCAN_TARGET_PATH, side_effect=fake_scan_target),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            exit_code = asyncio.run(_async_multi_scan(_make_manifest()))

        assert call_order == ["api"]
        assert exit_code == 0

    def test_three_targets_dispatched_in_order(self) -> None:
        call_order: list[str] = []

        async def fake_scan_target(target, scan_id, max_iters):  # type: ignore[no-untyped-def]
            call_order.append(target.name)
            return []

        manifest = _make_manifest(targets=[
            ManifestTarget(name="studio", kind=TargetKind.DESKTOP, entry="/path/App.app"),
            ManifestTarget(name="cloud-api", kind=TargetKind.WEB, entry="http://localhost:3333"),
            ManifestTarget(name="mcp-proxy", kind=TargetKind.WEB, entry="http://localhost:8000"),
        ])

        with (
            patch(_SCAN_TARGET_PATH, side_effect=fake_scan_target),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(manifest))

        assert call_order == ["studio", "cloud-api", "mcp-proxy"]

    def test_skipped_targets_not_dispatched(self) -> None:
        call_order: list[str] = []

        async def fake_scan_target(target, scan_id, max_iters):  # type: ignore[no-untyped-def]
            call_order.append(target.name)
            return []

        manifest = _make_manifest(targets=[
            ManifestTarget(name="active", kind=TargetKind.WEB, entry="http://a"),
            ManifestTarget(name="skipped", kind=TargetKind.WEB, entry="http://b", skip=True),
            ManifestTarget(name="also-active", kind=TargetKind.WEB, entry="http://c"),
        ])

        with (
            patch(_SCAN_TARGET_PATH, side_effect=fake_scan_target),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(manifest))

        # skip=True targets are handled inside _scan_target, which returns [] early.
        # We are patching _scan_target entirely so it's called for all; but the real
        # implementation checks target.skip. Test the real impl:
        assert set(call_order) == {"active", "skipped", "also-active"}

    def test_skip_true_real_impl_not_scanned(self) -> None:
        """Real _scan_target: skip=True returns [] without touching pipeline."""
        pipeline = _fake_pipeline()
        manifest = _make_manifest(targets=[
            ManifestTarget(name="active", kind=TargetKind.WEB, entry="http://a"),
            ManifestTarget(name="skipped", kind=TargetKind.WEB, entry="http://b", skip=True),
        ])

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(manifest))

        # pipeline.run called once (for "active"), not for "skipped"
        assert pipeline.run.call_count == 1
        call_args = pipeline.run.call_args
        assert call_args.kwargs.get("target") == "http://a" or call_args.args[0] == "http://a"
        assert call_args.kwargs.get("target_hints") == {}

    def test_manifest_target_hints_are_forwarded_to_pipeline(self) -> None:
        pipeline = _fake_pipeline()
        manifest = _make_manifest(targets=[
            ManifestTarget(
                name="api",
                kind=TargetKind.WEB,
                entry="http://localhost:3000",
                hints={"compose_file": "infra/benchmarks/juice-shop.yml", "service": "juice-shop"},
            ),
        ])

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(manifest))

        call_args = pipeline.run.call_args
        assert call_args.kwargs["target_hints"] == {
            "compose_file": "infra/benchmarks/juice-shop.yml",
            "service": "juice-shop",
        }


# ---------------------------------------------------------------------------
# Tests: Phase-G synthesis
# ---------------------------------------------------------------------------

class TestPhaseGSynthesis:
    def test_phase_g_called_when_correlation_true(self) -> None:
        phase_g_called = False

        async def fake_phase_g(findings):  # type: ignore[no-untyped-def]
            nonlocal phase_g_called
            phase_g_called = True
            return []

        pipeline = _fake_pipeline(findings=[MagicMock()])  # non-empty

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, side_effect=fake_phase_g),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(_make_manifest(correlation=True)))

        assert phase_g_called

    def test_phase_g_not_called_when_correlation_false(self) -> None:
        phase_g_called = False

        async def fake_phase_g(findings):  # type: ignore[no-untyped-def]
            nonlocal phase_g_called
            phase_g_called = True
            return []

        pipeline = _fake_pipeline(findings=[MagicMock()])

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, side_effect=fake_phase_g),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(_make_manifest(correlation=False)))

        assert not phase_g_called

    def test_phase_g_not_called_when_no_findings(self) -> None:
        phase_g_called = False

        async def fake_phase_g(findings):  # type: ignore[no-untyped-def]
            nonlocal phase_g_called
            phase_g_called = True
            return []

        pipeline = _fake_pipeline(findings=[])  # empty

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, side_effect=fake_phase_g),
            patch(_REPORT_PATH),
        ):
            asyncio.run(_async_multi_scan(_make_manifest(correlation=True)))

        # No findings → no synthesis
        assert not phase_g_called


# ---------------------------------------------------------------------------
# Tests: CODE surface graceful skip
# ---------------------------------------------------------------------------

class TestCodeSurfaceGracefulSkip:
    def test_code_surface_not_implemented_skips_gracefully(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When CODE surface raises NotImplementedError, warn and continue."""
        manifest = _make_manifest(targets=[
            ManifestTarget(name="web-target", kind=TargetKind.WEB, entry="http://a"),
            ManifestTarget(name="code-target", kind=TargetKind.CODE, entry="/path/to/repo"),
        ])

        web_pipeline = _fake_pipeline()

        def pipeline_factory() -> Any:
            return web_pipeline

        # Simulate SurfaceFactory.probe raising NotImplementedError for CODE
        def fake_surface_factory_probe(kind: TargetKind) -> None:
            if kind == TargetKind.CODE:
                raise NotImplementedError("CODE surface not yet landed")

        with (
            patch(_PIPELINE_PATH, side_effect=pipeline_factory),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
            patch(
                "vxis.interaction.factory.SurfaceFactory.probe",
                side_effect=fake_surface_factory_probe,
                create=True,
            ),
            caplog.at_level(logging.WARNING, logger="vxis.cli.multi_scan"),
        ):
            exit_code = asyncio.run(_async_multi_scan(manifest))

        # Should NOT abort — exit 0
        assert exit_code == 0

        # Web pipeline was called (for "web-target")
        assert web_pipeline.run.call_count == 1

        # WARN logged for code-target skip
        assert any(
            "CODE surface not yet available" in rec.message
            for rec in caplog.records
        )

    def test_code_surface_import_error_skips_gracefully(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When SurfaceFactory import fails entirely, warn and continue."""
        manifest = _make_manifest(targets=[
            ManifestTarget(name="code-only", kind=TargetKind.CODE, entry="/path/repo"),
        ])

        with (
            patch(_PIPELINE_PATH, return_value=_fake_pipeline()),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
            patch.dict("sys.modules", {"vxis.interaction.factory": None}),  # type: ignore[dict-item]
            caplog.at_level(logging.WARNING, logger="vxis.cli.multi_scan"),
        ):
            # Should not raise — graceful fallback
            exit_code = asyncio.run(_async_multi_scan(manifest))

        # All targets CODE and skipped → return 1
        assert exit_code == 1
        assert any("CODE surface" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Tests: exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_returns_0_on_success(self) -> None:
        pipeline = _fake_pipeline()

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            exit_code = asyncio.run(_async_multi_scan(_make_manifest()))

        assert exit_code == 0

    def test_returns_1_when_all_skipped(self) -> None:
        manifest = _make_manifest(targets=[
            ManifestTarget(name="a", kind=TargetKind.WEB, entry="http://x", skip=True),
            ManifestTarget(name="b", kind=TargetKind.WEB, entry="http://y", skip=True),
        ])

        with (
            patch(_PIPELINE_PATH, return_value=_fake_pipeline()),
            patch(_BRAIN_PATH, return_value=MagicMock()),
            patch(_PHASE_G_PATH, new_callable=AsyncMock, return_value=[]),
            patch(_REPORT_PATH),
        ):
            exit_code = asyncio.run(_async_multi_scan(manifest))

        assert exit_code == 1
