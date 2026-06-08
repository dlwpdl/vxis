from vxis.p1.models import Scope
from vxis.p1.scope import ScopeDecision, classify, matches


def test_exact_domain_in_allow():
    assert matches("app.acme.com", ["app.acme.com"]) is True


def test_wildcard_domain():
    assert matches("api.acme-staging.com", ["*.acme-staging.com"]) is True


def test_cidr_membership():
    assert matches("10.0.0.12", ["10.0.0.0/24"]) is True
    assert matches("10.0.1.12", ["10.0.0.0/24"]) is False


def test_deny_overrides_allow():
    scope = Scope(allow=["10.0.0.0/24"], deny=["10.0.0.5"])
    assert classify("10.0.0.5", scope) is ScopeDecision.DENIED
    assert classify("10.0.0.6", scope) is ScopeDecision.ALLOWED
