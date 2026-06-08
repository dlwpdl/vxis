from __future__ import annotations

from typing import Any, Protocol

from vxis.p1.audit import AuditLog
from vxis.p1.enforcer import enforce
from vxis.p1.models import Engagement
from vxis.p1.resolver import Resolver


class CapabilityAdapter(Protocol):
    def execute(self, *, technique: str, target: str, options: dict[str, Any]) -> Any: ...

    def teardown(self, engagement_id: str) -> None: ...


class DryRunAdapter:
    def execute(self, *, technique: str, target: str, options: dict[str, Any]) -> dict[str, Any]:
        return {
            "dry_run": True,
            "technique": technique,
            "target": target,
            "options": dict(options),
        }

    def teardown(self, engagement_id: str) -> None:
        return None


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
    return adapter.execute(technique=technique, target=target, options=options or {})
