import pytest
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.scope.loader import ScopeLoader
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.runtime_gate import set_active_scope, clear_active_scope

class _Tool:
    name = "http_request"
    description = "x"
    input_schema = {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}
    def __init__(self): self.ran = False
    async def run(self, **kwargs): self.ran = True; return ToolResult(ok=True, summary="ran")

@pytest.fixture(autouse=True)
def _reset():
    clear_active_scope(); yield; clear_active_scope()

def _scope(in_scope):
    cfg = ScopeLoader.safe_default(); cfg.in_scope_domains = in_scope
    return ScopeEnforcer(cfg)

@pytest.mark.asyncio
async def test_dispatch_blocks_out_of_scope():
    reg = ToolRegistry(); tool = _Tool(); reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("http_request", {"url": "http://evil.com/"})
    assert res.ok is False and res.error == "scope_blocked" and tool.ran is False

@pytest.mark.asyncio
async def test_dispatch_allows_in_scope():
    reg = ToolRegistry(); tool = _Tool(); reg.register(tool)
    set_active_scope(_scope(["app.acme.com"]))
    res = await reg.dispatch("http_request", {"url": "http://app.acme.com/x"})
    assert res.ok is True and tool.ran is True

@pytest.mark.asyncio
async def test_dispatch_no_scope_runs_normally():
    reg = ToolRegistry(); tool = _Tool(); reg.register(tool)
    res = await reg.dispatch("http_request", {"url": "http://anything.com/"})
    assert res.ok is True and tool.ran is True
