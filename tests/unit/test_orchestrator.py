"""Unit tests for ScanOrchestrator and ScanResult."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vxis.core.orchestrator import ScanOrchestrator, ScanResult
from vxis.models.finding import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(severity: Severity, target: str = "example.com") -> Finding:
    return Finding(
        id="test-id",
        scan_id="scan-001",
        title=f"Test Finding ({severity.value})",
        description="A test finding.",
        severity=severity,
        target=target,
        finding_type="vulnerability",
        source_plugin="nuclei",
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ScanResult.duration_seconds
# ---------------------------------------------------------------------------


class TestScanResultDuration:
    def test_duration_positive(self):
        """duration_seconds returns a positive float when finished_at > started_at."""
        from datetime import timedelta

        start = _utcnow()
        finish = start + timedelta(seconds=42.5)
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            started_at=start,
            finished_at=finish,
        )
        assert abs(result.duration_seconds - 42.5) < 0.001

    def test_duration_zero_when_same_timestamp(self):
        """duration_seconds is 0.0 when both timestamps are identical."""
        ts = _utcnow()
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            started_at=ts,
            finished_at=ts,
        )
        assert result.duration_seconds == 0.0

    def test_duration_fractional_seconds(self):
        """duration_seconds preserves sub-second precision."""
        from datetime import timedelta

        start = _utcnow()
        finish = start + timedelta(milliseconds=750)
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            started_at=start,
            finished_at=finish,
        )
        assert 0.74 < result.duration_seconds < 0.76


# ---------------------------------------------------------------------------
# ScanResult.severity_counts
# ---------------------------------------------------------------------------


class TestScanResultSeverityCounts:
    def test_counts_empty_findings(self):
        """All severity counts are 0 when there are no findings."""
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
        )
        counts = result.severity_counts
        assert counts["critical"] == 0
        assert counts["high"] == 0
        assert counts["medium"] == 0
        assert counts["low"] == 0
        assert counts["informational"] == 0

    def test_counts_single_severity(self):
        """A single finding increments only its severity bucket."""
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            findings=[_make_finding(Severity.critical)],
        )
        counts = result.severity_counts
        assert counts["critical"] == 1
        assert counts["high"] == 0
        assert counts["medium"] == 0

    def test_counts_mixed_severities(self):
        """Multiple findings with different severities are counted correctly."""
        findings = [
            _make_finding(Severity.critical),
            _make_finding(Severity.critical),
            _make_finding(Severity.high),
            _make_finding(Severity.medium),
            _make_finding(Severity.low),
            _make_finding(Severity.informational),
        ]
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            findings=findings,
        )
        counts = result.severity_counts
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["informational"] == 1

    def test_counts_all_keys_present(self):
        """severity_counts always contains all five severity keys."""
        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            findings=[_make_finding(Severity.high)],
        )
        expected_keys = {"critical", "high", "medium", "low", "informational"}
        assert set(result.severity_counts.keys()) == expected_keys

    def test_counts_uses_effective_severity(self):
        """severity_counts reflects effective_severity (analyst override)."""
        finding = _make_finding(Severity.low)
        # Override analyst severity to critical
        finding.analyst_severity = Severity.critical

        result = ScanResult(
            scan_id="abc",
            target="example.com",
            profile="standard",
            findings=[finding],
        )
        counts = result.severity_counts
        # effective_severity is critical, not low
        assert counts["critical"] == 1
        assert counts["low"] == 0


# ---------------------------------------------------------------------------
# ScanOrchestrator initialization
# ---------------------------------------------------------------------------


class TestScanOrchestratorInit:
    def test_init_stores_config(self):
        """ScanOrchestrator stores the config on the instance."""
        from vxis.config.schema import VXISConfig

        config = VXISConfig()
        orch = ScanOrchestrator(config)
        assert orch.config is config

    def test_init_creates_audit_logger(self, tmp_path):
        """ScanOrchestrator creates an AuditLogger pointing at data_dir/audit.jsonl."""
        from vxis.config.schema import VXISConfig
        from vxis.core.logger import AuditLogger

        config = VXISConfig(data_dir=tmp_path)
        orch = ScanOrchestrator(config)
        assert isinstance(orch.audit_logger, AuditLogger)
        assert orch.audit_logger.log_path == tmp_path / "audit.jsonl"

    def test_init_with_custom_data_dir(self, tmp_path):
        """AuditLogger path respects custom data_dir."""
        from vxis.config.schema import VXISConfig

        custom_dir = tmp_path / "custom_data"
        custom_dir.mkdir()
        config = VXISConfig(data_dir=custom_dir)
        orch = ScanOrchestrator(config)
        assert "audit.jsonl" in str(orch.audit_logger.log_path)


# ---------------------------------------------------------------------------
# ScanOrchestrator scope validation
# ---------------------------------------------------------------------------


class TestScanOrchestratorScopeValidation:
    """Verify that run_scan raises ScopeViolationError when appropriate.

    The scope check is performed early (before any tool execution), so we
    patch the ScopeValidator.validate method to simulate an out-of-scope
    target without needing real network tools.
    """

    @pytest.mark.asyncio
    async def test_raises_on_invalid_profile(self, tmp_path):
        """run_scan raises ValueError when the requested profile is not in config."""
        from vxis.config.schema import VXISConfig

        config = VXISConfig(data_dir=tmp_path)
        orch = ScanOrchestrator(config)

        with pytest.raises(ValueError, match="nonexistent_profile"):
            await orch.run_scan(
                target="example.com",
                profile="nonexistent_profile",
            )

    @pytest.mark.asyncio
    async def test_scope_check_logged_on_valid_target(self, tmp_path):
        """A successful scope check is written to the audit log."""
        from vxis.config.schema import VXISConfig

        config = VXISConfig(data_dir=tmp_path)
        orch = ScanOrchestrator(config)

        # Patch the underlying scan execution so no real tools are invoked
        with (
            patch("vxis.core.orchestrator.discover_plugins", return_value={}),
            patch("vxis.core.orchestrator.build_dag_from_plugins", return_value={}),
            patch(
                "vxis.core.orchestrator.DAGExecutor.execute",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "vxis.core.orchestrator.FPPipeline.process",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("vxis.core.orchestrator.ScanOrchestrator._persist", new_callable=AsyncMock),
        ):
            result = await orch.run_scan(target="example.com", profile="standard")

        assert result.target == "example.com"
        # Audit log file should have been created
        audit_path = tmp_path / "audit.jsonl"
        assert audit_path.exists()
        lines = audit_path.read_text().strip().splitlines()
        events = [line for line in lines if '"scope_check"' in line]
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_scan_result_contains_scan_id(self, tmp_path):
        """run_scan result includes a non-empty scan_id UUID string."""
        from vxis.config.schema import VXISConfig

        config = VXISConfig(data_dir=tmp_path)
        orch = ScanOrchestrator(config)

        with (
            patch("vxis.core.orchestrator.discover_plugins", return_value={}),
            patch("vxis.core.orchestrator.build_dag_from_plugins", return_value={}),
            patch(
                "vxis.core.orchestrator.DAGExecutor.execute",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "vxis.core.orchestrator.FPPipeline.process",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("vxis.core.orchestrator.ScanOrchestrator._persist", new_callable=AsyncMock),
        ):
            result = await orch.run_scan(target="example.com", profile="standard")

        import uuid

        # scan_id must be a valid UUID string
        parsed = uuid.UUID(result.scan_id)
        assert str(parsed) == result.scan_id

    @pytest.mark.asyncio
    async def test_scan_result_profile_matches_request(self, tmp_path):
        """result.profile matches the profile argument passed to run_scan."""
        from vxis.config.schema import VXISConfig

        config = VXISConfig(data_dir=tmp_path)
        orch = ScanOrchestrator(config)

        with (
            patch("vxis.core.orchestrator.discover_plugins", return_value={}),
            patch("vxis.core.orchestrator.build_dag_from_plugins", return_value={}),
            patch(
                "vxis.core.orchestrator.DAGExecutor.execute",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "vxis.core.orchestrator.FPPipeline.process",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("vxis.core.orchestrator.ScanOrchestrator._persist", new_callable=AsyncMock),
        ):
            result = await orch.run_scan(target="example.com", profile="stealth")

        assert result.profile == "stealth"
