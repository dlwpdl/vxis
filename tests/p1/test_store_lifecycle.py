import pytest

from vxis.p1.lifecycle import LifecycleError, activate, close, expire_if_due
from vxis.p1.models import Engagement, Policy, Scope, State, Window
from vxis.p1.store import EngagementStore


def _eng(state=State.DRAFT, attested=True, expiry="2026-06-18"):
    return Engagement(
        id="e1",
        name="ACME-2026Q2",
        operator="BAC",
        scope=Scope(allow=["app.acme.com"]),
        window=Window(start="2026-06-01", expiry=expiry),
        policy=Policy(techniques=["recon"]),
        state=state,
        attested=attested,
    )


def test_store_round_trips_engagement(tmp_path):
    store = EngagementStore(tmp_path)
    engagement = activate(_eng())
    store.save(engagement)
    loaded = store.load("e1")
    assert loaded.id == "e1"
    assert loaded.operator == "BAC"
    assert loaded.state is State.ACTIVE


def test_activate_requires_attestation():
    with pytest.raises(LifecycleError, match="attest"):
        activate(_eng(attested=False))


def test_close_fires_teardown():
    fired = []
    closed = close(_eng(state=State.ACTIVE), teardown=lambda eng: fired.append(eng.id))
    assert closed.state is State.CLOSED
    assert fired == ["e1"]


def test_expire_if_due_fires_teardown():
    fired = []
    expired = expire_if_due(
        _eng(state=State.ACTIVE, expiry="2026-06-01"),
        now="2026-06-02T00:00:00Z",
        teardown=lambda eng: fired.append(eng.id),
    )
    assert expired.state is State.EXPIRED
    assert fired == ["e1"]
