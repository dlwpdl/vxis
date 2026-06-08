from __future__ import annotations

from typing import Any, Protocol

from vxis.p1.audit import AuditLog
from vxis.p1.enforcer import enforce
from vxis.p1.models import Engagement
from vxis.p1.resolver import Resolver
from vxis.p1.store import EngagementStore


class CapabilityAdapter(Protocol):
    def execute(self, *, technique: str, target: str, options: dict[str, Any]) -> Any: ...

    def teardown(self, beacon_id: str) -> None: ...


class DryRunAdapter:
    def execute(self, *, technique: str, target: str, options: dict[str, Any]) -> dict[str, Any]:
        return {
            "dry_run": True,
            "technique": technique,
            "target": target,
            "options": dict(options),
        }

    def teardown(self, beacon_id: str) -> None:
        return None


class LiveAdapter:
    """Placeholder for vetted external capability orchestration.

    VXIS does not author implant/evasion code here. Live mode stays refused
    until an approved adapter is registered behind the P1 enforcer.
    """

    def execute(self, *, technique: str, target: str, options: dict[str, Any]) -> Any:
        raise NotImplementedError(f"no authorized live adapter registered for technique '{technique}'")

    def teardown(self, beacon_id: str) -> None:
        return None


def resolve_adapter(*, live: bool, technique: str) -> CapabilityAdapter:
    return LiveAdapter() if live else DryRunAdapter()


def run_capability(
    engagement: Engagement,
    adapter: CapabilityAdapter,
    *,
    technique: str,
    target: str,
    options: dict[str, Any] | None = None,
    resolver: Resolver,
    audit: AuditLog,
    now: str,
    destructive: bool = False,
    store: EngagementStore | None = None,
) -> Any:
    enforce(
        engagement,
        technique=technique,
        target=target,
        destructive=destructive,
        resolver=resolver,
        audit=audit,
        now=now,
        action="capability",
        metadata={"adapter": adapter.__class__.__name__},
    )
    result = adapter.execute(technique=technique, target=target, options=options or {})
    beacon_id = result.get("beacon_id") if isinstance(result, dict) else None
    if beacon_id:
        engagement.beacons.append(str(beacon_id))
        if store is not None:
            store.save(engagement)
    return result
