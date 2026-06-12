import pytest
from vxis.scope.loader import ScopeLoader
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.runtime_gate import set_active_scope, clear_active_scope, enforce_scope_invocation
from vxis.scope.runtime_gate import build_target_scope_enforcer


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


def test_check_url_recovers_host_from_schemeless_target():
    # A bare "host:port" / hostname (e.g. nmap_scan target="localhost:3000") must not
    # be falsely blocked when the host IS in scope. urlparse otherwise reads the host
    # as the scheme and yields hostname=None, failing the in-scope match.
    enf = _enforcer(["localhost"])
    assert enf.check_url("localhost:3000").allowed is True
    assert enf.check_url("localhost").allowed is True

    enf_ip = _enforcer(["127.0.0.1"])
    assert enf_ip.check_url("127.0.0.1:8080").allowed is True

    # Out-of-scope host is still correctly denied (host recovered, just not matching).
    assert enf.check_url("evil.com:80").allowed is False


def test_offline_tool_skipped():
    set_active_scope(_enforcer(["app.acme.com"]))
    assert enforce_scope_invocation("report_finding", {"target": "evil.com"}) is None


def test_destructive_blocked_without_approval():
    set_active_scope(_enforcer(["app.acme.com"]))
    d = enforce_scope_invocation(
        "http_request", {"url": "http://app.acme.com/x", "method": "DELETE"}
    )
    assert d is not None and d.allowed is False


def test_approval_required_passes_when_approved():
    set_active_scope(_enforcer(["app.acme.com"]), approve_destructive=True)
    d = enforce_scope_invocation(
        "http_request", {"url": "http://app.acme.com/upload", "method": "POST"}
    )
    assert d is not None and d.allowed is True


@pytest.fixture
def _isolated_scope_env(monkeypatch, tmp_path):
    """Isolate scope loading from any real ./vxis-scope.json or ~/.vxis/scopes/* files."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    yield


def test_build_enforcer_injects_target_host_when_empty(_isolated_scope_env):
    enf = build_target_scope_enforcer("http://app.acme.com:3000/login", scope_arg=None)
    assert "app.acme.com" in enf.scope.in_scope_domains
    assert enf.check_url("http://evil.com/").allowed is False
    assert enf.check_url("http://app.acme.com/x").allowed is True


def test_build_enforcer_bare_host_without_scheme(_isolated_scope_env):
    enf = build_target_scope_enforcer("localhost:3000", scope_arg=None)
    assert "localhost" in enf.scope.in_scope_domains
    assert enf.check_url("http://evil.com/").allowed is False
    assert enf.check_url("http://localhost:3000/x").allowed is True
