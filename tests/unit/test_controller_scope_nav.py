"""Unit tests: scope gate on browser navigations in InteractionController.

Tests _navigate_checked() directly via object.__new__ + minimal attribute injection
so the full controller start() / browser / network stack is never exercised.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from vxis.scope.runtime_gate import set_active_scope, clear_active_scope
from vxis.scope.loader import ScopeLoader
from vxis.scope.enforcer import ScopeEnforcer


# ── helpers ─────────────────────────────────────────────────────────


def _enforcer(in_scope: list[str]) -> ScopeEnforcer:
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = in_scope
    return ScopeEnforcer(cfg)


def _make_controller(target: str = "http://app.acme.com"):
    """Build a bare InteractionController with only the attributes needed by
    _navigate_checked: self._page."""
    from vxis.interaction.controller import InteractionController

    ctrl = object.__new__(InteractionController)
    # Minimal page fake: navigate records calls and returns a sentinel.
    page = MagicMock()
    page.navigate = AsyncMock(return_value=MagicMock(title="ok", js_errors=[]))
    ctrl._page = page
    ctrl._target = target.rstrip("/")
    return ctrl


# ── fixture ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_scope():
    clear_active_scope()
    yield
    clear_active_scope()


# ── tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_active_scope_navigates_freely():
    """No ambient scope → gate returns None → page.navigate is called."""
    ctrl = _make_controller()
    await ctrl._navigate_checked("http://app.acme.com/x")
    ctrl._page.navigate.assert_awaited_once_with("http://app.acme.com/x")


@pytest.mark.asyncio
async def test_active_scope_in_scope_host_navigates():
    """Active scope [app.acme.com] + in-scope URL → navigate proceeds."""
    set_active_scope(_enforcer(["app.acme.com"]))
    ctrl = _make_controller()
    await ctrl._navigate_checked("http://app.acme.com/login")
    ctrl._page.navigate.assert_awaited_once_with("http://app.acme.com/login")


@pytest.mark.asyncio
async def test_active_scope_out_of_scope_host_blocked():
    """Active scope [app.acme.com] + evil.com URL → ScopeBlockedError, no navigate."""
    from vxis.interaction.hands import ScopeBlockedError

    set_active_scope(_enforcer(["app.acme.com"]))
    ctrl = _make_controller()

    with pytest.raises(ScopeBlockedError):
        await ctrl._navigate_checked("http://evil.com/")

    ctrl._page.navigate.assert_not_awaited()
