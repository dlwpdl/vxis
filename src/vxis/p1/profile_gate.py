from __future__ import annotations

from datetime import datetime

from vxis.config.schema import resolve_scan_profile
from vxis.p1.enforcer import assert_engagement_active
from vxis.p1.ghost_binding import apply_ghost
from vxis.p1.models import Engagement
from vxis.p1.store import EngagementStore


class P1ProfileGateError(Exception):
    pass


def profile_requires_engagement(profile: str) -> bool:
    try:
        scan_profile = resolve_scan_profile(profile)
    except KeyError:
        return False
    return bool(getattr(scan_profile, "requires_engagement", False))


def require_profile_engagement(
    profile: str,
    engagement_id: str | None,
    *,
    store: EngagementStore | None = None,
    now: str | datetime | None = None,
) -> Engagement | None:
    if not profile_requires_engagement(profile):
        return None
    if not engagement_id:
        raise P1ProfileGateError(f"profile '{profile}' requires --engagement")
    resolved_store = store or EngagementStore()
    try:
        engagement = resolved_store.load(engagement_id)
    except FileNotFoundError as exc:
        raise P1ProfileGateError(f"engagement '{engagement_id}' not found") from exc
    try:
        assert_engagement_active(engagement, now=now)
    except Exception as exc:
        raise P1ProfileGateError(f"engagement '{engagement_id}' is not active: {exc}") from exc
    try:
        from vxis.ghost.layer import ghost_layer

        apply_ghost(engagement, ghost=ghost_layer)
    except Exception as exc:
        raise P1ProfileGateError(f"failed to apply P1 ghost policy: {exc}") from exc
    return engagement
