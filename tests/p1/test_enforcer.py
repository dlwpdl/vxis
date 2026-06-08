import pytest

from vxis.p1.audit import AuditLog
from vxis.p1.enforcer import EnforcementError, enforce
from vxis.p1.models import Engagement, Policy, Scope, State, Window
from vxis.p1.resolver import FakeResolver


def _eng():
    return Engagement(
        id="eng_acme",
        name="ACME-2026Q2",
        operator="BAC",
        scope=Scope(allow=["app.acme.com", "10.0.0.0/24"], deny=["payments.acme.com", "10.0.0.5"]),
        window=Window(start="2026-06-01", expiry="2026-06-18"),
        policy=Policy(techniques=["recon", "c2"], intensity="stealth", destructive=False),
        state=State.ACTIVE,
        attested=True,
    )


def _ctx(tmp_path):
    return {
        "resolver": FakeResolver({"app.acme.com": ["10.0.0.12"], "sneaky.acme.com": ["10.0.0.5"]}),
        "audit": AuditLog(tmp_path / "audit.jsonl"),
        "now": "2026-06-10T10:00:00Z",
    }


def test_allows_in_scope_and_audits(tmp_path):
    ctx = _ctx(tmp_path)
    enforce(_eng(), technique="c2", target="app.acme.com", **ctx)
    entries = ctx["audit"].read()
    assert entries[-1]["decision"] == "ALLOW"
    assert entries[-1]["operator"] == "BAC"
    assert entries[-1]["resolved_targets"] == ["app.acme.com", "10.0.0.12"]


def test_rejects_out_of_scope_and_audits_reject(tmp_path):
    ctx = _ctx(tmp_path)
    with pytest.raises(EnforcementError, match="out of scope"):
        enforce(_eng(), technique="c2", target="evil.com", **ctx)
    assert ctx["audit"].read()[-1]["decision"] == "REJECT"


def test_rejects_denied_resolved_ip(tmp_path):
    ctx = _ctx(tmp_path)
    with pytest.raises(EnforcementError, match="excluded"):
        enforce(_eng(), technique="c2", target="sneaky.acme.com", **ctx)
    assert "10.0.0.5" in ctx["audit"].read()[-1]["reason"]


def test_rejects_expired_window(tmp_path):
    ctx = _ctx(tmp_path)
    ctx["now"] = "2026-07-01T10:00:00Z"
    with pytest.raises(EnforcementError, match="expired"):
        enforce(_eng(), technique="c2", target="app.acme.com", **ctx)


def test_rejects_unauthorized_technique(tmp_path):
    with pytest.raises(EnforcementError, match="technique"):
        enforce(_eng(), technique="exfil", target="app.acme.com", **_ctx(tmp_path))


def test_rejects_destructive_action_by_default(tmp_path):
    with pytest.raises(EnforcementError, match="destructive"):
        enforce(_eng(), technique="c2", target="app.acme.com", destructive=True, **_ctx(tmp_path))
