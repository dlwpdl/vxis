"""Dashboard scan manager — background scan execution + SSE streaming.

Manages scan lifecycle from the dashboard:
1. Start scan in background asyncio task
2. Collect events via ScanEventBus → ScanSnapshotCollector
3. Stream progress via SSE to dashboard
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from vxis.config.schema import VXISConfig
from vxis.core.events import ScanEventBus, ScanSnapshotCollector, ScanEvent
from vxis.core.orchestrator import ScanOrchestrator, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class ManagedScan:
    """A scan being managed by the dashboard."""

    scan_id: str
    target: str
    profile: str
    scan_type: str
    status: str = "starting"  # starting, running, completed, failed
    task: asyncio.Task | None = None
    collector: ScanSnapshotCollector = field(default_factory=ScanSnapshotCollector)
    event_bus: ScanEventBus = field(default_factory=ScanEventBus)
    result: ScanResult | None = None
    error: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # SSE subscribers: list of asyncio.Queue that receive event dicts
    subscribers: list[asyncio.Queue] = field(default_factory=list)


# Plugin presets per scan type
SCAN_TYPE_PLUGINS: dict[str, list[str] | None] = {
    "zero_touch": ["shodan", "crtsh", "subfinder", "dnstwist", "httpx"],
    "external": [
        "nuclei",
        "nmap",
        "httpx",
        "testssl",
        "checkdmarc",
        "wafw00f",
        "trufflehog",
        "sslyze",
        "subfinder",
        "crtsh",
        "dnstwist",
        "shodan",
    ],
    "internal": ["nmap", "bloodhound", "certipy", "netexec"],
    "code": [
        "semgrep",
        "bandit",
        "checkov",
        "poutine",
        "actionlint",
        "gitleaks",
        "confused",
        "trivy",
    ],
    "cloud": ["prowler", "s3scanner", "trivy_k8s", "kube_bench"],
    "full": None,  # all plugins
}

SCAN_TYPE_PROFILES: dict[str, str] = {
    "zero_touch": "passive",
    "external": "standard",
    "internal": "standard",
    "code": "standard",
    "cloud": "standard",
    "full": "standard",
}

SCAN_TYPE_LABELS: dict[str, str] = {
    "zero_touch": "제로터치 (Passive)",
    "external": "외부 스캔",
    "internal": "내부 스캔",
    "code": "코드/공급망 스캔",
    "cloud": "클라우드 스캔",
    "full": "전체 스캔",
}


class ScanManager:
    """Singleton manager for dashboard-initiated scans."""

    def __init__(self) -> None:
        self._scans: dict[str, ManagedScan] = {}
        self._config: VXISConfig | None = None

    def _get_config(self) -> VXISConfig:
        if self._config is None:
            self._config = VXISConfig()
        return self._config

    @property
    def active_scans(self) -> list[ManagedScan]:
        return [s for s in self._scans.values() if s.status in ("starting", "running")]

    @property
    def all_scans(self) -> list[ManagedScan]:
        return list(self._scans.values())

    def get_scan(self, scan_id: str) -> ManagedScan | None:
        return self._scans.get(scan_id)

    async def start_scan(
        self,
        target: str,
        scan_type: str = "external",
        profile: str | None = None,
    ) -> ManagedScan:
        """Start a scan in the background and return the ManagedScan handle."""
        import uuid

        scan_id = str(uuid.uuid4())[:8]
        resolved_profile = profile or SCAN_TYPE_PROFILES.get(scan_type, "standard")
        plugins = SCAN_TYPE_PLUGINS.get(scan_type)

        managed = ManagedScan(
            scan_id=scan_id,
            target=target,
            profile=resolved_profile,
            scan_type=scan_type,
        )

        # Wire up event bus → collector + SSE broadcast
        managed.event_bus.on_any(managed.collector.handle_event)
        managed.event_bus.on_any(self._make_sse_broadcaster(managed))

        self._scans[scan_id] = managed

        # Launch background task
        managed.task = asyncio.create_task(
            self._run_scan(managed, plugins),
            name=f"scan-{scan_id}",
        )

        return managed

    async def _run_scan(
        self,
        managed: ManagedScan,
        plugins: list[str] | None,
    ) -> None:
        """Execute the scan in background."""
        config = self._get_config()
        orchestrator = ScanOrchestrator(config, event_bus=managed.event_bus)

        from vxis.scope.runtime_gate import (
            build_target_scope_enforcer,
            clear_active_scope,
            set_active_scope,
        )

        managed.status = "running"
        set_active_scope(build_target_scope_enforcer(managed.target))
        try:
            result = await orchestrator.run_scan(
                target=managed.target,
                profile=managed.profile,
                selected_plugins=plugins,
            )
            managed.result = result
            managed.status = "completed"

            # Notify SSE subscribers of completion
            await self._broadcast(
                managed,
                {
                    "event": "scan_completed",
                    "findings": len(result.findings),
                    "duration": f"{result.duration_seconds:.1f}s",
                },
            )

        except Exception as exc:
            managed.status = "failed"
            managed.error = str(exc)
            logger.exception("Dashboard scan %s failed", managed.scan_id)

            await self._broadcast(
                managed,
                {
                    "event": "scan_failed",
                    "error": str(exc),
                },
            )
        finally:
            clear_active_scope()

    def _make_sse_broadcaster(self, managed: ManagedScan):
        """Create an event handler that broadcasts to SSE subscribers."""

        async def _handler(event: ScanEvent) -> None:
            snapshot = managed.collector.snapshot
            data = {
                "event": event.event_type.value,
                "progress": f"{snapshot.progress_fraction:.0%}",
                "completed": snapshot.completed_count,
                "total": snapshot.total_count,
                "running": snapshot.running_count,
                "findings": snapshot.total_findings,
                "severity": snapshot.severity_counts,
                "stage": snapshot.pipeline_stage,
                "elapsed": f"{snapshot.elapsed_seconds:.0f}s",
            }

            # Add plugin-specific info for node events
            if hasattr(event, "plugin_name") and event.plugin_name:
                plugin = snapshot.plugins.get(event.plugin_name)
                if plugin:
                    data["plugin"] = {
                        "name": plugin.name,
                        "state": plugin.state,
                        "finding_count": plugin.finding_count,
                    }

            await self._broadcast(managed, data)

        return _handler

    async def _broadcast(self, managed: ManagedScan, data: dict) -> None:
        """Send data to all SSE subscribers."""
        dead = []
        for i, queue in enumerate(managed.subscribers):
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                dead.append(i)
        # Clean up dead subscribers
        for i in reversed(dead):
            managed.subscribers.pop(i)

    def subscribe(self, scan_id: str) -> asyncio.Queue | None:
        """Subscribe to SSE events for a scan. Returns a Queue or None."""
        managed = self._scans.get(scan_id)
        if managed is None:
            return None
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        managed.subscribers.append(queue)
        return queue


# Module-level singleton
scan_manager = ScanManager()
