from __future__ import annotations

from typing import Protocol

from vxis.p1.models import Engagement


class GhostLayerLike(Protocol):
    def activate(self, proxy_pool: list[str] | None = None) -> None: ...

    def deactivate(self) -> None: ...

    def is_active(self) -> bool: ...


_ANONYMIZE_BY_INTENSITY = {
    "stealth": True,
    "standard": True,
    "loud": False,
}


def apply_ghost(engagement: Engagement, *, ghost: GhostLayerLike) -> None:
    """Bind P1 intensity to the target-facing ghost layer.

    The audit operator remains the customer-visible handle, e.g. BAC.
    """
    anonymize = _ANONYMIZE_BY_INTENSITY.get(engagement.policy.intensity.lower(), True)
    if anonymize and not ghost.is_active():
        ghost.activate()
    elif not anonymize and ghost.is_active():
        ghost.deactivate()
