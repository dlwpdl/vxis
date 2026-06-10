"""Per-hop egress scope-gate enforcement in Hands (TargetSession).

The ambient scope gate is enforced at tool dispatch, but the ACTUAL HTTP egress
happens inside ``TargetSession.request`` via an httpx client with
``follow_redirects=True``. Redirects (incl. SSRF 302 → metadata), RequestChain
steps, crawl_links, and skill-internal requests all flow through this one client.

These tests verify an httpx ``request`` event hook scope-checks EVERY outgoing
request — initial AND every redirect hop — and that an out-of-scope egress is
blocked LOUDLY (fail-closed) before the transport ever serves the bad host.

Uses ``httpx.MockTransport`` (no network) injected via the ``transport`` param.
"""

from __future__ import annotations

import httpx
import pytest

from vxis.interaction.hands import ScopeBlockedError, TargetSession
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.loader import ScopeLoader
from vxis.scope.runtime_gate import clear_active_scope, set_active_scope


@pytest.fixture(autouse=True)
def _reset_scope():
    """Clear ambient scope before AND after each test (ContextVar isolation)."""
    clear_active_scope()
    yield
    clear_active_scope()


def _enforcer(in_scope: list[str]) -> ScopeEnforcer:
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = in_scope
    return ScopeEnforcer(cfg)


@pytest.mark.asyncio
async def test_no_ambient_scope_is_noop():
    """No set_active_scope → hook returns None path → request to ANY host succeeds."""
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(str(request.url))
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    session = TargetSession(base_url="http://anything.example", transport=transport)
    try:
        resp = await session.request("GET", "/x")
    finally:
        await session.close()

    assert resp.status == 200
    assert served == ["http://anything.example/x"]


@pytest.mark.asyncio
async def test_in_scope_request_allowed():
    """Active scope [app.acme.com]; in-scope GET → 200, reaches transport."""
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(str(request.url))
        return httpx.Response(200, text="hello")

    set_active_scope(_enforcer(["app.acme.com"]))
    transport = httpx.MockTransport(handler)
    session = TargetSession(base_url="http://app.acme.com", transport=transport)
    try:
        resp = await session.request("GET", "/x")
    finally:
        await session.close()

    assert resp.status == 200
    assert served == ["http://app.acme.com/x"]


@pytest.mark.asyncio
async def test_out_of_scope_absolute_request_blocked():
    """Active scope [app.acme.com]; absolute request to evil.com → blocked,
    transport NEVER serves evil.com."""
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(str(request.url))
        return httpx.Response(200, text="should-not-happen")

    set_active_scope(_enforcer(["app.acme.com"]))
    transport = httpx.MockTransport(handler)
    session = TargetSession(base_url="http://app.acme.com", transport=transport)
    try:
        with pytest.raises(ScopeBlockedError):
            await session.request("GET", "http://evil.com/")
    finally:
        await session.close()

    assert all("evil.com" not in s for s in served)


@pytest.mark.asyncio
async def test_redirect_hop_to_out_of_scope_blocked():
    """THE KEY CASE: in-scope first hop 302s to evil.com. follow_redirects=True
    attempts the evil.com hop → hook fires for evil.com → blocked. The evil.com
    hop must never reach the transport."""
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(str(request.url))
        if request.url.host == "app.acme.com":
            return httpx.Response(302, headers={"Location": "http://evil.com/"})
        # evil.com — must never be reached
        return httpx.Response(200, text="metadata-secret")

    set_active_scope(_enforcer(["app.acme.com"]))
    transport = httpx.MockTransport(handler)
    session = TargetSession(base_url="http://app.acme.com", transport=transport)
    try:
        with pytest.raises(ScopeBlockedError):
            await session.request("GET", "/redirect")
    finally:
        await session.close()

    # First hop (in scope) was served; the redirect hop to evil.com was blocked.
    assert "http://app.acme.com/redirect" in served
    assert all("evil.com" not in s for s in served)
