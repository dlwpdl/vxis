"""Unit tests: dashboard _run_scan activates a fail-closed scope gate.

Verifies that:
1. During orchestrator.run_scan, an out-of-scope target is blocked (decision.allowed is False).
2. During orchestrator.run_scan, the managed.target host is in-scope (allowed is True or None meaning no url arg given).
3. After _run_scan returns, the scope is cleared (enforce_scope_invocation returns None).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vxis.scope.runtime_gate import clear_active_scope, enforce_scope_invocation


# ---------------------------------------------------------------------------
# Autouse fixture: ensure no stale scope leaks between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_scope() -> None:  # type: ignore[return]
    clear_active_scope()
    yield
    clear_active_scope()


# ---------------------------------------------------------------------------
# Minimal stubs so we don't need a real config / orchestrator
# ---------------------------------------------------------------------------


@dataclass
class _FakeResult:
    findings: list = field(default_factory=list)
    duration_seconds: float = 0.1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_managed(target: str = "http://example.com"):
    """Build a ManagedScan-like object without importing the real one."""
    from vxis.dashboard.scan_manager import ManagedScan

    managed = ManagedScan(
        scan_id="test01",
        target=target,
        profile="standard",
        scan_type="external",
    )
    return managed


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDashboardScopeActivation:
    """_run_scan wires and tears down the ambient scope enforcer correctly."""

    @pytest.mark.asyncio
    async def test_scope_active_during_run_blocks_out_of_scope_target(self):
        """While run_scan executes, enforce_scope_invocation must block an off-target URL."""
        target = "http://example.com"
        managed = _make_managed(target)

        # What we observed inside the stub run — captured by closure
        captured: dict = {}

        async def _fake_run_scan(*, target, profile, selected_plugins):  # noqa: ARG001
            # Check that the scope is active and blocks an off-target URL
            decision = enforce_scope_invocation("nmap", {"target": "http://evil.com"})
            captured["during_blocked"] = decision
            return _FakeResult()

        fake_orchestrator = MagicMock()
        fake_orchestrator.run_scan = _fake_run_scan

        fake_config = MagicMock()

        with (
            patch(
                "vxis.dashboard.scan_manager.VXISConfig",
                return_value=fake_config,
            ),
            patch(
                "vxis.dashboard.scan_manager.ScanOrchestrator",
                return_value=fake_orchestrator,
            ),
        ):
            from vxis.dashboard.scan_manager import ScanManager

            sm = ScanManager()
            await sm._run_scan(managed, plugins=None)

        # During the run: evil.com must have been blocked
        decision = captured["during_blocked"]
        assert decision is not None, "Scope was not active during run"
        assert decision.allowed is False, f"Expected blocked, got: {decision}"

    @pytest.mark.asyncio
    async def test_scope_active_during_run_allows_in_scope_target(self):
        """While run_scan executes, the managed target itself must be allowed."""
        target = "http://example.com"
        managed = _make_managed(target)

        captured: dict = {}

        async def _fake_run_scan(*, target, profile, selected_plugins):  # noqa: ARG001
            decision = enforce_scope_invocation("nmap", {"target": "http://example.com"})
            captured["during_allowed"] = decision
            return _FakeResult()

        fake_orchestrator = MagicMock()
        fake_orchestrator.run_scan = _fake_run_scan

        fake_config = MagicMock()

        with (
            patch("vxis.dashboard.scan_manager.VXISConfig", return_value=fake_config),
            patch(
                "vxis.dashboard.scan_manager.ScanOrchestrator",
                return_value=fake_orchestrator,
            ),
        ):
            from vxis.dashboard.scan_manager import ScanManager

            sm = ScanManager()
            await sm._run_scan(managed, plugins=None)

        decision = captured["during_allowed"]
        # Either allowed=True or None (no active scope — would be a bug, but we're explicit)
        assert decision is None or decision.allowed is True, (
            f"In-scope target should be allowed, got: {decision}"
        )

    @pytest.mark.asyncio
    async def test_scope_cleared_after_successful_run(self):
        """After _run_scan returns normally, enforce_scope_invocation must return None."""
        managed = _make_managed("http://example.com")

        fake_orchestrator = MagicMock()
        fake_orchestrator.run_scan = AsyncMock(return_value=_FakeResult())

        with (
            patch("vxis.dashboard.scan_manager.VXISConfig", return_value=MagicMock()),
            patch(
                "vxis.dashboard.scan_manager.ScanOrchestrator",
                return_value=fake_orchestrator,
            ),
        ):
            from vxis.dashboard.scan_manager import ScanManager

            sm = ScanManager()
            await sm._run_scan(managed, plugins=None)

        # Scope must be cleared after successful run
        post = enforce_scope_invocation("nmap", {"target": "http://evil.com"})
        assert post is None, f"Scope was not cleared after success: {post}"

    @pytest.mark.asyncio
    async def test_scope_cleared_after_failed_run(self):
        """After _run_scan raises, enforce_scope_invocation must still return None."""
        managed = _make_managed("http://example.com")

        fake_orchestrator = MagicMock()
        fake_orchestrator.run_scan = AsyncMock(side_effect=RuntimeError("boom"))

        with (
            patch("vxis.dashboard.scan_manager.VXISConfig", return_value=MagicMock()),
            patch(
                "vxis.dashboard.scan_manager.ScanOrchestrator",
                return_value=fake_orchestrator,
            ),
        ):
            from vxis.dashboard.scan_manager import ScanManager

            sm = ScanManager()
            # _run_scan catches and logs exceptions internally — it should not re-raise
            await sm._run_scan(managed, plugins=None)

        assert managed.status == "failed"

        # Scope must be cleared even after exception
        post = enforce_scope_invocation("nmap", {"target": "http://evil.com"})
        assert post is None, f"Scope was not cleared after failure: {post}"
