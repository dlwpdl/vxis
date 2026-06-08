from __future__ import annotations

from datetime import datetime
from typing import Callable

from vxis.p1.models import Engagement, State, parse_utc_datetime

Teardown = Callable[[Engagement], None]


class LifecycleError(Exception):
    pass


def activate(engagement: Engagement) -> Engagement:
    if not engagement.attested:
        raise LifecycleError("cannot activate: engagement not attested")
    if engagement.state is not State.DRAFT:
        raise LifecycleError(f"cannot activate from state {engagement.state.value}")
    engagement.state = State.ACTIVE
    return engagement


def close(engagement: Engagement, teardown: Teardown | None = None) -> Engagement:
    if teardown is not None:
        teardown(engagement)
    engagement.state = State.CLOSED
    return engagement


def expire_if_due(
    engagement: Engagement,
    *,
    now: str | datetime,
    teardown: Teardown | None = None,
) -> Engagement:
    if engagement.state is State.ACTIVE and parse_utc_datetime(now) > parse_utc_datetime(
        engagement.window.expiry,
        end_of_day=True,
    ):
        if teardown is not None:
            teardown(engagement)
        engagement.state = State.EXPIRED
    return engagement
