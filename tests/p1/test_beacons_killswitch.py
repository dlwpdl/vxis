from vxis.p1.lifecycle import close
from vxis.p1.models import Engagement, Policy, Scope, State, Window
from vxis.p1.store import EngagementStore
from vxis.p1.teardown import build_teardown


def _eng() -> Engagement:
    return Engagement(
        id="eng_t",
        name="T",
        operator="BAC",
        scope=Scope(allow=["app.acme.com"]),
        window=Window(start="2026-06-01", expiry="2099-01-01"),
        policy=Policy(techniques=["c2"], intensity="stealth"),
        state=State.ACTIVE,
        attested=True,
    )


class _Adapter:
    def __init__(self) -> None:
        self.torn: list[str] = []

    def teardown(self, beacon_id: str) -> None:
        self.torn.append(beacon_id)


class _Ghost:
    def __init__(self) -> None:
        self.active = True

    def is_active(self) -> bool:
        return self.active

    def deactivate(self) -> None:
        self.active = False


def test_beacons_default_empty() -> None:
    assert _eng().beacons == []


def test_beacons_survive_store_roundtrip(tmp_path) -> None:
    store = EngagementStore(tmp_path)
    engagement = _eng()
    engagement.beacons.append("beacon-1")
    store.save(engagement)

    assert store.load("eng_t").beacons == ["beacon-1"]


def test_close_tears_down_beacons_and_ghost() -> None:
    engagement = _eng()
    engagement.beacons.extend(["b1", "b2"])
    adapter = _Adapter()
    ghost = _Ghost()

    close(engagement, teardown=build_teardown(adapter=adapter, ghost=ghost))

    assert adapter.torn == ["b1", "b2"]
    assert engagement.beacons == []
    assert ghost.active is False
    assert engagement.state is State.CLOSED
