"""Unit tests: _scan_target activates a fail-closed per-target scope gate.

Verifies that:
1. During pipeline.run, an out-of-scope target is blocked (decision.allowed is False).
2. During pipeline.run, the target.entry host is in-scope (allowed is True).
3. After _scan_target returns normally, the scope is cleared (enforce_scope_invocation returns None).
4. After _scan_target raises (pipeline.run explodes), the scope is still cleared.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vxis.cli.manifest import ManifestTarget
from vxis.cli.multi_scan import _scan_target
from vxis.interaction.surface import TargetKind
from vxis.scope.runtime_gate import clear_active_scope, enforce_scope_invocation


# ---------------------------------------------------------------------------
# Autouse fixture: ensure no stale scope leaks between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_scope():  # type: ignore[return]
    clear_active_scope()
    yield
    clear_active_scope()


# ---------------------------------------------------------------------------
# Minimal stubs
# ---------------------------------------------------------------------------


@dataclass
class _FakeCtx:
    findings: list[Any] = field(default_factory=list)
    scan_id: str = "VXIS-TEST-001"
    target: str = "http://example.com"


def _make_target(
    entry: str = "http://example.com",
    name: str = "api",
    kind: TargetKind = TargetKind.WEB,
    skip: bool = False,
) -> ManifestTarget:
    return ManifestTarget(name=name, kind=kind, entry=entry, skip=skip)


_PIPELINE_PATH = "vxis.cli.multi_scan._build_pipeline"
_BRAIN_PATH = "vxis.cli.multi_scan._build_brain"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScanTargetScopeActivation:
    """_scan_target wires and tears down the per-target ambient scope correctly."""

    @pytest.mark.asyncio
    async def test_scope_active_during_run_blocks_out_of_scope_target(self):
        """While pipeline.run executes, enforce_scope_invocation must block an off-target URL."""
        target = _make_target(entry="http://example.com")
        captured: dict = {}

        async def _fake_pipeline_run(**kwargs: Any) -> _FakeCtx:  # noqa: ARG001
            decision = enforce_scope_invocation("nmap", {"target": "http://evil.com"})
            captured["during_blocked"] = decision
            return _FakeCtx()

        pipeline = MagicMock()
        pipeline.run = _fake_pipeline_run

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
        ):
            await _scan_target(target=target, scan_id="VXIS-TEST-001", max_iters=5)

        decision = captured["during_blocked"]
        assert decision is not None, "Scope was not active during pipeline.run"
        assert decision.allowed is False, f"Expected evil.com to be blocked, got: {decision}"

    @pytest.mark.asyncio
    async def test_scope_active_during_run_allows_in_scope_target(self):
        """While pipeline.run executes, the target.entry host itself must be allowed."""
        entry = "http://example.com"
        target = _make_target(entry=entry)
        captured: dict = {}

        async def _fake_pipeline_run(**kwargs: Any) -> _FakeCtx:  # noqa: ARG001
            decision = enforce_scope_invocation("nmap", {"target": entry})
            captured["during_allowed"] = decision
            return _FakeCtx()

        pipeline = MagicMock()
        pipeline.run = _fake_pipeline_run

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
        ):
            await _scan_target(target=target, scan_id="VXIS-TEST-001", max_iters=5)

        decision = captured["during_allowed"]
        assert decision is None or decision.allowed is True, (
            f"In-scope entry should be allowed, got: {decision}"
        )

    @pytest.mark.asyncio
    async def test_scope_cleared_after_successful_run(self):
        """After _scan_target returns normally, enforce_scope_invocation returns None."""
        target = _make_target(entry="http://example.com")

        pipeline = MagicMock()
        pipeline.run = AsyncMock(return_value=_FakeCtx())

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
        ):
            await _scan_target(target=target, scan_id="VXIS-TEST-001", max_iters=5)

        post = enforce_scope_invocation("nmap", {"target": "http://evil.com"})
        assert post is None, f"Scope was not cleared after successful run: {post}"

    @pytest.mark.asyncio
    async def test_scope_cleared_after_failed_run(self):
        """After pipeline.run raises, clear_active_scope is still called (finally block)."""
        target = _make_target(entry="http://example.com")

        pipeline = MagicMock()
        pipeline.run = AsyncMock(side_effect=RuntimeError("pipeline exploded"))

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
        ):
            with pytest.raises(RuntimeError, match="pipeline exploded"):
                await _scan_target(target=target, scan_id="VXIS-TEST-001", max_iters=5)

        post = enforce_scope_invocation("nmap", {"target": "http://evil.com"})
        assert post is None, f"Scope was not cleared after exception: {post}"

    @pytest.mark.asyncio
    async def test_skip_target_does_not_activate_scope(self):
        """skip=True targets return early — scope must never be activated."""
        target = _make_target(entry="http://example.com", skip=True)

        pipeline = MagicMock()
        pipeline.run = AsyncMock(return_value=_FakeCtx())

        with (
            patch(_PIPELINE_PATH, return_value=pipeline),
            patch(_BRAIN_PATH, return_value=MagicMock()),
        ):
            findings = await _scan_target(target=target, scan_id="VXIS-TEST-001", max_iters=5)

        assert findings == []
        # pipeline.run was never called (skip=True returns early before scope activation)
        pipeline.run.assert_not_called()
        # Scope must be clear (was never set)
        post = enforce_scope_invocation("nmap", {"target": "http://example.com"})
        assert post is None, "Scope should not be set for skipped targets"

    @pytest.mark.asyncio
    async def test_each_target_gets_its_own_scope(self):
        """Two sequential targets each see only their own host in scope."""
        target_a = _make_target(entry="http://alpha.example.com", name="alpha")
        target_b = _make_target(entry="http://beta.example.com", name="beta")

        decisions: dict[str, Any] = {}

        async def _fake_run_a(**kwargs: Any) -> _FakeCtx:  # noqa: ARG001
            decisions["a_blocks_b"] = enforce_scope_invocation(
                "nmap", {"target": "http://beta.example.com"}
            )
            decisions["a_allows_a"] = enforce_scope_invocation(
                "nmap", {"target": "http://alpha.example.com"}
            )
            return _FakeCtx()

        async def _fake_run_b(**kwargs: Any) -> _FakeCtx:  # noqa: ARG001
            decisions["b_blocks_a"] = enforce_scope_invocation(
                "nmap", {"target": "http://alpha.example.com"}
            )
            decisions["b_allows_b"] = enforce_scope_invocation(
                "nmap", {"target": "http://beta.example.com"}
            )
            return _FakeCtx()

        pipeline_a = MagicMock()
        pipeline_a.run = _fake_run_a
        pipeline_b = MagicMock()
        pipeline_b.run = _fake_run_b

        pipeline_iter = iter([pipeline_a, pipeline_b])

        with (
            patch(_PIPELINE_PATH, side_effect=lambda: next(pipeline_iter)),
            patch(_BRAIN_PATH, return_value=MagicMock()),
        ):
            await _scan_target(target=target_a, scan_id="VXIS-TEST-A", max_iters=5)
            await _scan_target(target=target_b, scan_id="VXIS-TEST-B", max_iters=5)

        # alpha scope blocks beta
        assert decisions["a_blocks_b"] is not None
        assert decisions["a_blocks_b"].allowed is False

        # alpha scope allows alpha
        assert decisions["a_allows_a"] is None or decisions["a_allows_a"].allowed is True

        # beta scope blocks alpha
        assert decisions["b_blocks_a"] is not None
        assert decisions["b_blocks_a"].allowed is False

        # beta scope allows beta
        assert decisions["b_allows_b"] is None or decisions["b_allows_b"].allowed is True

        # After both runs, scope must be clear
        post = enforce_scope_invocation("nmap", {"target": "http://alpha.example.com"})
        assert post is None, "Scope leaked after sequential target runs"
