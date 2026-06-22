import pytest

from vxis.p1.audit import AuditLog
from vxis.p1.enforcer import EnforcementError, enforce
from vxis.p1.ghost_binding import apply_ghost
from vxis.p1.models import Engagement, Policy, Scope, State, Window
from vxis.p1.resolver import FakeResolver


def _eng(intensity: str) -> Engagement:
    return Engagement(
        id="eng_i",
        name="I",
        operator="BAC",
        scope=Scope(allow=["app.acme.com"]),
        window=Window(start="2026-06-01", expiry="2099-01-01"),
        policy=Policy(techniques=["recon"], intensity=intensity),
        state=State.ACTIVE,
        attested=True,
    )


def _ctx(tmp_path):
    return {
        "resolver": FakeResolver({"app.acme.com": ["10.0.0.1"]}),
        "audit": AuditLog(tmp_path / "audit.jsonl"),
        "now": "2026-06-10T00:00:00Z",
    }


class _Ghost:
    def __init__(self) -> None:
        self.active = False

    def activate(self, proxy_pool=None) -> None:
        self.active = True

    def deactivate(self) -> None:
        self.active = False

    def is_active(self) -> bool:
        return self.active


def test_valid_intensity_allows(tmp_path) -> None:
    entry = enforce(_eng("stealth"), technique="recon", target="app.acme.com", **_ctx(tmp_path))

    assert entry["decision"] == "ALLOW"
    assert entry["target"] == "app.acme.com"


def test_unknown_intensity_rejected(tmp_path) -> None:
    with pytest.raises(EnforcementError, match="intensity"):
        enforce(_eng("nuclear"), technique="recon", target="app.acme.com", **_ctx(tmp_path))


def test_stealth_activates_ghost_and_preserves_operator() -> None:
    ghost = _Ghost()
    engagement = _eng("stealth")

    apply_ghost(engagement, ghost=ghost)

    assert ghost.is_active() is True
    assert engagement.operator == "BAC"


def test_loud_deactivates_ghost() -> None:
    ghost = _Ghost()
    ghost.activate()

    apply_ghost(_eng("loud"), ghost=ghost)

    assert ghost.is_active() is False
