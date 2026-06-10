import pytest
from vxis.scope.loader import ScopeLoader
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.runtime_gate import set_active_scope, clear_active_scope, enforce_scope_invocation

@pytest.fixture(autouse=True)
def _reset():
    clear_active_scope()
    yield
    clear_active_scope()

def _enforcer(in_scope):
    cfg = ScopeLoader.safe_default()
    cfg.in_scope_domains = in_scope
    return ScopeEnforcer(cfg)

def test_no_active_scope_returns_none():
    assert enforce_scope_invocation("http_request", {"url": "http://x.com"}) is None

def test_in_scope_target_allowed():
    set_active_scope(_enforcer(["app.acme.com"]))
    d = enforce_scope_invocation("http_request", {"url": "http://app.acme.com/login"})
    assert d is not None and d.allowed is True

def test_out_of_scope_host_blocked():
    set_active_scope(_enforcer(["app.acme.com"]))
    d = enforce_scope_invocation("http_request", {"url": "http://evil.com/"})
    assert d is not None and d.allowed is False

def test_offline_tool_skipped():
    set_active_scope(_enforcer(["app.acme.com"]))
    assert enforce_scope_invocation("report_finding", {"target": "evil.com"}) is None

def test_destructive_blocked_without_approval():
    set_active_scope(_enforcer(["app.acme.com"]))
    d = enforce_scope_invocation("http_request", {"url": "http://app.acme.com/x", "method": "DELETE"})
    assert d is not None and d.allowed is False

def test_approval_required_passes_when_approved():
    set_active_scope(_enforcer(["app.acme.com"]), approve_destructive=True)
    d = enforce_scope_invocation("http_request", {"url": "http://app.acme.com/upload", "method": "POST"})
    assert d is not None and d.allowed is True
