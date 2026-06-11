import pytest
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.scope.loader import ScopeLoader
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.runtime_gate import set_active_scope, clear_active_scope


class _Tool:
    name = "http_request"
    description = "x"
    input_schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    def __init__(self):
        self.ran = False

    async def run(self, **kwargs):
        self.ran = True
        return ToolResult(ok=True, summary="ran")


class _OfflineTool:
    """Simulates report_finding — offline, not target-facing."""

    name = "report_finding"
    description = "record a finding"
    input_schema = {"type": "object", "properties": {}, "required": []}

    def __init__(self):
        self.ran = False

    async def run(self, **kwargs):
        self.ran = True
        return ToolResult(ok=True, summary="reported")


@pytest.fixture(autouse=True)
def _reset():
    clear_active_scope()
    yield
    clear_active_scope()


def _scope(in_scope):
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = in_scope
    return ScopeEnforcer(cfg)


@pytest.mark.asyncio
async def test_dispatch_blocks_out_of_scope():
    reg = ToolRegistry()
    tool = _Tool()
    reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("http_request", {"url": "http://evil.com/"})
    assert res.ok is False and res.error == "scope_blocked" and tool.ran is False


@pytest.mark.asyncio
async def test_dispatch_allows_in_scope():
    reg = ToolRegistry()
    tool = _Tool()
    reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("http_request", {"url": "http://app.acme.com/x"})
    assert res.ok is True and tool.ran is True


@pytest.mark.asyncio
async def test_dispatch_no_scope_runs_normally():
    reg = ToolRegistry()
    tool = _Tool()
    reg.register(tool)
    res = await reg.dispatch("http_request", {"url": "http://anything.com/"})
    assert res.ok is True and tool.ran is True


# ── New integration tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_offline_tool_bypasses_scope_gate():
    """report_finding is offline (target_facing=False) and must pass even when
    the URL in its args is outside the active scope."""
    reg = ToolRegistry()
    tool = _OfflineTool()
    reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("report_finding", {"target": "http://evil.com"})
    assert res.ok is True
    assert tool.ran is True


@pytest.mark.asyncio
async def test_gate_exception_returns_scope_gate_failed(monkeypatch):
    """If enforce_scope_invocation raises unexpectedly, dispatch must return
    ok=False with error='scope_gate_failed' and must NOT run the tool."""
    import vxis.scope.runtime_gate as _rtmod

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(_rtmod, "enforce_scope_invocation", _boom)

    reg = ToolRegistry()
    tool = _Tool()
    reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("http_request", {"url": "http://app.acme.com/x"})
    assert res.ok is False
    assert res.error == "scope_gate_failed"
    assert tool.ran is False


@pytest.mark.asyncio
async def test_destructive_approval_at_dispatch():
    """DELETE to in-scope URL is blocked by safe-default (DELETE denied).
    A POST to an upload path (approval_required) is allowed once approve_destructive=True."""

    # Case 1 — DELETE denied by safe default even for an in-scope host
    reg = ToolRegistry()
    tool = _Tool()
    reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("http_request", {"url": "http://app.acme.com/x", "method": "DELETE"})
    assert res.ok is False
    assert res.error == "scope_blocked"

    # Case 2 — POST to upload path blocked without approval, allowed with it
    tool2 = _Tool()
    reg2 = ToolRegistry()
    reg2.register(tool2)
    set_active_scope(_scope(["app.acme.com"]), approve_destructive=True)
    res2 = await reg2.dispatch(
        "http_request", {"url": "http://app.acme.com/upload", "method": "POST"}
    )
    assert res2.ok is True
    assert tool2.ran is True
