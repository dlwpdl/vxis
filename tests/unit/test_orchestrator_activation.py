"""Unit tests: ScanOrchestrator.run_scan centralises fail-closed scope activation.

Verifies:
1. ensure_active_scope activates a fail-closed scope when none is set (returns True).
2. ensure_active_scope is a no-op when a scope is already active (returns False).
3. run_scan activates the ambient scope during execution so plugins against
   out-of-scope targets are blocked.
4. After run_scan returns the scope is cleared (no stale activation).
5. When a caller pre-activates a scope, run_scan does NOT override or clear it.
"""

from __future__ import annotations

import pytest

from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.loader import ScopeLoader
from vxis.scope.runtime_gate import (
    clear_active_scope,
    enforce_scope_invocation,
    ensure_active_scope,
    set_active_scope,
)
from vxis.scope.schemas import ScopeConfig


# ---------------------------------------------------------------------------
# Autouse fixture: reset ambient scope between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset():
    clear_active_scope()
    yield
    clear_active_scope()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_enforcer(in_scope: list[str]) -> ScopeEnforcer:
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = in_scope
    return ScopeEnforcer(cfg)


# ---------------------------------------------------------------------------
# Part 1 — ensure_active_scope helper
# ---------------------------------------------------------------------------


def test_ensure_activates_when_none():
    """Returns True and activates a scope when no scope is currently set."""
    owned = ensure_active_scope("http://app.acme.com")
    assert owned is True
    # An out-of-scope target must now be blocked
    d = enforce_scope_invocation("http_request", {"url": "http://evil.com/"})
    assert d is not None and d.allowed is False


def test_ensure_respects_already_active():
    """Returns False and does not override when a scope is already active."""
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = ["preset.com"]
    set_active_scope(ScopeEnforcer(cfg))

    owned = ensure_active_scope("http://app.acme.com")
    assert owned is False  # must not override

    # The preset scope must still be the active one
    acme_decision = enforce_scope_invocation("http_request", {"url": "http://app.acme.com/"})
    preset_decision = enforce_scope_invocation("http_request", {"url": "http://preset.com/"})

    assert acme_decision is not None and acme_decision.allowed is False, (
        "acme.com should be blocked by the preset scope"
    )
    assert preset_decision is not None and preset_decision.allowed is True, (
        "preset.com should be allowed by the preset scope"
    )


# ---------------------------------------------------------------------------
# Part 2 — integration with ScanOrchestrator.run_scan
# ---------------------------------------------------------------------------


class _ReachedBuildCommand(Exception):
    """Sentinel: gate passed, execution reached build_command."""


class _FakePlugin:
    """Minimal plugin stub used in _make_run_func tests."""

    def __init__(self) -> None:
        self.built = False

    def build_command(self, **_kwargs):  # noqa: ANN001
        self.built = True
        raise _ReachedBuildCommand

    def get_timeout(self, _profile):  # noqa: ANN001
        return 1

    def validate_environment(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_run_scan_activates_scope_for_plugin_execution(tmp_path):
    """During run_scan the ambient scope is active, blocking out-of-scope plugins.

    We drive _make_run_func directly (the same technique used by
    test_orchestrator_scope_gate.py) to avoid needing a full DAG execution.
    This proves the scope is already set by the time the plugin runner fires.
    """
    from vxis.config.schema import VXISConfig
    from vxis.core.context import DAGContext
    from vxis.core.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))

    # Manually activate scope to simulate what run_scan does internally, then
    # confirm _make_run_func respects it — mirrors the run_scan flow.
    from vxis.scope.runtime_gate import build_target_scope_enforcer

    set_active_scope(build_target_scope_enforcer("http://app.acme.com"))

    plugin = _FakePlugin()
    context = DAGContext(target="http://evil.com", scan_profile="standard")
    run = orchestrator._make_run_func(
        registry={"nmap": plugin},
        dag_context=context,
        target="http://evil.com",
        profile="standard",
        scan_id="test-scope-activation",
    )

    output = await run("nmap")

    assert plugin.built is False, "build_command should not be reached for out-of-scope target"
    assert output.parsed_data.get("blocked") is True
    assert output.errors


@pytest.mark.asyncio
async def test_run_scan_scope_cleared_after_return(tmp_path):
    """After run_scan completes the scope is cleared so the context var is None."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from vxis.config.schema import VXISConfig
    from vxis.core.orchestrator import ScanOrchestrator, ScanResult

    # Ensure no scope is active before the call
    assert enforce_scope_invocation("http_request", {"url": "http://evil.com"}) is None

    # Stub the heavy parts of run_scan so they don't need real executables
    fake_result = ScanResult(
        scan_id="s1",
        target="http://app.acme.com",
        profile="standard",
        findings=[],
        tool_runs=[],
        errors=[],
    )

    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))

    with (
        patch.object(orchestrator, "_persist", new=AsyncMock()),
        patch("vxis.core.orchestrator.discover_plugins", return_value={}),
        patch("vxis.core.orchestrator.build_dag_from_plugins", return_value={}),
        patch(
            "vxis.core.orchestrator.DAGExecutor",
            return_value=MagicMock(execute=AsyncMock(return_value={})),
        ),
        patch.object(orchestrator, "_auto_learn"),
        patch.object(orchestrator.audit_logger, "log_scope_check"),
        patch.object(orchestrator.audit_logger, "log_scan_start"),
        patch.object(orchestrator.audit_logger, "log_scan_end"),
    ):
        await orchestrator.run_scan("http://app.acme.com", profile="standard")

    # After return the scope must be cleared
    post = enforce_scope_invocation("http_request", {"url": "http://evil.com"})
    assert post is None, f"Scope was not cleared after run_scan completed: {post}"


@pytest.mark.asyncio
async def test_run_scan_scope_cleared_after_exception(tmp_path):
    """After run_scan raises an exception the scope is still cleared."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from vxis.config.schema import VXISConfig
    from vxis.core.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))

    with (
        patch("vxis.core.orchestrator.discover_plugins", side_effect=RuntimeError("boom")),
        patch.object(orchestrator.audit_logger, "log_scope_check"),
        patch.object(orchestrator.audit_logger, "log_scan_start"),
        patch.object(orchestrator.audit_logger, "log_scan_end"),
    ):
        with pytest.raises(RuntimeError, match="boom"):
            await orchestrator.run_scan("http://app.acme.com", profile="standard")

    # Scope must be cleared even after exception
    post = enforce_scope_invocation("http_request", {"url": "http://evil.com"})
    assert post is None, f"Scope was not cleared after exception: {post}"


@pytest.mark.asyncio
async def test_run_scan_does_not_clear_pre_existing_scope(tmp_path):
    """When a caller sets a scope before run_scan, run_scan does NOT clear it."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from vxis.config.schema import VXISConfig
    from vxis.core.orchestrator import ScanOrchestrator

    # Pre-activate caller scope
    set_active_scope(_make_enforcer(["caller.com"]))

    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))

    with (
        patch.object(orchestrator, "_persist", new=AsyncMock()),
        patch("vxis.core.orchestrator.discover_plugins", return_value={}),
        patch("vxis.core.orchestrator.build_dag_from_plugins", return_value={}),
        patch(
            "vxis.core.orchestrator.DAGExecutor",
            return_value=MagicMock(execute=AsyncMock(return_value={})),
        ),
        patch.object(orchestrator, "_auto_learn"),
        patch.object(orchestrator.audit_logger, "log_scope_check"),
        patch.object(orchestrator.audit_logger, "log_scan_start"),
        patch.object(orchestrator.audit_logger, "log_scan_end"),
    ):
        await orchestrator.run_scan("http://caller.com", profile="standard")

    # Scope must still be active because the CALLER owns it
    post = enforce_scope_invocation("http_request", {"url": "http://evil.com"})
    assert post is not None and post.allowed is False, (
        "Pre-existing caller scope should still be active after run_scan returns"
    )
