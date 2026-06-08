from __future__ import annotations

from typing import Protocol

from vxis.p1.models import Engagement


class BeaconAdapter(Protocol):
    def teardown(self, beacon_id: str) -> None: ...


class GhostLayerLike(Protocol):
    def is_active(self) -> bool: ...

    def deactivate(self) -> None: ...


def build_teardown(
    *,
    adapter: BeaconAdapter | None = None,
    ghost: GhostLayerLike | None = None,
):
    """Build the engagement killswitch hook.

    It tears down live adapter state and deactivates target-facing ghosting.
    Operator attribution and the audit trail are intentionally untouched.
    """

    def _teardown(engagement: Engagement) -> None:
        for beacon_id in list(engagement.beacons):
            if adapter is not None:
                adapter.teardown(beacon_id)
        engagement.beacons.clear()
        if ghost is not None and ghost.is_active():
            ghost.deactivate()

    return _teardown
