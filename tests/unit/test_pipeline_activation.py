"""Unit tests: ScanPipeline.run activates the ambient scope gate for the resolved target.

Verifies three properties wired into ScanPipeline.run via ensure_active_scope:

(a) DURING run, enforce_scope_invocation("http_request", {"url": "http://evil.com/"})
    is blocked when the resolved target is app.acme.com.
(b) AFTER run returns, the scope is cleared (enforce_scope_invocation returns None).
(c) If a caller pre-activates a scope, run() does NOT clear it (ensure_active_scope
    returns False = caller owns teardown, not us).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vxis.interaction.surface import TargetKind
from vxis.pipeline.launcher import RuntimeLaunch
from vxis.pipeline.scan_pipeline_v2 import ScanPipeline
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.loader import ScopeLoader
from vxis.scope.runtime_gate import (
    clear_active_scope,
    enforce_scope_invocation,
    set_active_scope,
)


# ---------------------------------------------------------------------------
# Autouse fixture: prevent scope leaks between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_scope():  # type: ignore[return]
    clear_active_scope()
    yield
    clear_active_scope()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_runtime(resolved: str = "http://app.acme.com") -> RuntimeLaunch:
    return RuntimeLaunch(
        kind=TargetKind.WEB,
        original_target=resolved,
        resolved_target=resolved,
        launcher_name="web_docker_aware",
        runtime_mode="docker_local_target",
        metadata={},
        shared_notes=[],
    )


def _make_fake_loop_result() -> dict:
    return {
        "completed": True,
        "iterations": 1,
        "findings": [],
        "messages": 2,
        "review_history": [],
        "branches": [],
    }


def _make_pipe() -> ScanPipeline:
    return ScanPipeline(brain=MagicMock(), auto_approve_injection=True, generate_report=False)


# ---------------------------------------------------------------------------
# (a) Scope is ACTIVE during run — out-of-scope URL is blocked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scope_blocks_out_of_scope_url_during_run():
    """enforce_scope_invocation must block http://evil.com/ while run() is executing."""
    pipe = _make_pipe()
    runtime = _make_runtime("http://app.acme.com")
    captured: dict = {}

    async def _fake_loop_run() -> dict:
        decision = enforce_scope_invocation("http_request", {"url": "http://evil.com/"})
        captured["decision"] = decision
        return _make_fake_loop_result()

    fake_state = MagicMock(messages=[])
    with (
        patch(
            "vxis.pipeline.scan_pipeline_v2.prepare_target_runtime",
            new=AsyncMock(return_value=runtime),
        ),
        patch(
            "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
            return_value={"target_known": False, "prior_scan_count": 0, "known_findings": []},
        ),
        patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls,
    ):
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(side_effect=_fake_loop_run)
        mock_loop.state = fake_state
        mock_loop_cls.return_value = mock_loop

        await pipe.run(target="http://app.acme.com", kind=TargetKind.WEB)

    decision = captured.get("decision")
    assert decision is not None, "Scope was not active during ScanPipeline.run()"
    assert decision.allowed is False, (
        f"http://evil.com/ should be blocked during run(), got: {decision}"
    )


# ---------------------------------------------------------------------------
# (b) Scope is CLEARED after run returns
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scope_cleared_after_run_returns():
    """After run() returns normally, no ambient scope must remain active."""
    pipe = _make_pipe()
    runtime = _make_runtime("http://app.acme.com")

    fake_state = MagicMock(messages=[])
    with (
        patch(
            "vxis.pipeline.scan_pipeline_v2.prepare_target_runtime",
            new=AsyncMock(return_value=runtime),
        ),
        patch(
            "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
            return_value={"target_known": False, "prior_scan_count": 0, "known_findings": []},
        ),
        patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls,
    ):
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=_make_fake_loop_result())
        mock_loop.state = fake_state
        mock_loop_cls.return_value = mock_loop

        await pipe.run(target="http://app.acme.com", kind=TargetKind.WEB)

    post = enforce_scope_invocation("http_request", {"url": "http://evil.com/"})
    assert post is None, f"Scope was not cleared after run() returned: {post}"


# ---------------------------------------------------------------------------
# (c) Pre-existing scope is NOT cleared by run()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preexisting_scope_not_cleared_by_run():
    """If a caller already has an active scope, run() must NOT clear it on exit."""
    # Pre-activate a caller-owned scope for a different host
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = ["owner.example.com"]
    caller_enforcer = ScopeEnforcer(cfg)
    set_active_scope(caller_enforcer)

    pipe = _make_pipe()
    runtime = _make_runtime("http://app.acme.com")

    fake_state = MagicMock(messages=[])
    with (
        patch(
            "vxis.pipeline.scan_pipeline_v2.prepare_target_runtime",
            new=AsyncMock(return_value=runtime),
        ),
        patch(
            "vxis.pipeline.scan_pipeline_v2._load_target_memory_profile",
            return_value={"target_known": False, "prior_scan_count": 0, "known_findings": []},
        ),
        patch("vxis.pipeline.scan_pipeline_v2.ScanAgentLoop") as mock_loop_cls,
    ):
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value=_make_fake_loop_result())
        mock_loop.state = fake_state
        mock_loop_cls.return_value = mock_loop

        await pipe.run(target="http://app.acme.com", kind=TargetKind.WEB)

    # The caller's scope must still be active — run() must NOT have cleared it
    post = enforce_scope_invocation("http_request", {"url": "http://owner.example.com/api"})
    assert post is not None, "Caller's pre-existing scope was cleared by run() — must not happen"
    assert post.allowed is True, (
        f"Caller's in-scope host should still be allowed: {post}"
    )
