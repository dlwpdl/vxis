"""Event system for real-time scan progress feedback.

Provides a typed event bus that the DAG engine, scanner, and orchestrator
emit to, and the CLI TUI / dashboard consume from.

Architecture:
    Engine/Scanner/Orchestrator  →  ScanEventBus  →  CLI TUI / Dashboard / Logging

Events are dataclasses for type safety and easy serialization.
Listeners are simple async callables registered per event type.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """All event types emitted during a scan session."""

    # DAG engine events
    NODE_QUEUED = "node.queued"
    NODE_WAITING = "node.waiting"  # Waiting for dependency
    NODE_STARTED = "node.started"
    NODE_PROGRESS = "node.progress"  # Mid-execution update (finding count, etc.)
    NODE_COMPLETED = "node.completed"
    NODE_FAILED = "node.failed"
    NODE_SKIPPED = "node.skipped"
    NODE_TIMED_OUT = "node.timed_out"

    # Scanner events (tool subprocess)
    TOOL_OUTPUT_LINE = "tool.output_line"  # Single line from tool stdout
    TOOL_FINDING = "tool.finding"  # Real-time finding detected

    # Pipeline events
    PIPELINE_STAGE = "pipeline.stage"  # Normalization, dedup, FP, enrich
    PIPELINE_METRIC = "pipeline.metric"  # Finding counts at each stage

    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"


# ---------------------------------------------------------------------------
# Event data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanEvent:
    """Base event with common fields."""

    event_type: EventType
    timestamp: float = field(default_factory=time.monotonic)
    scan_id: str = ""


@dataclass(frozen=True)
class NodeEvent(ScanEvent):
    """Event from DAG engine about a specific plugin node."""

    plugin_name: str = ""
    state: str = ""
    elapsed_seconds: float = 0.0
    error: str = ""
    # For progress events
    finding_count: int = 0
    detail: str = ""
    # Dependency info
    waiting_for: str = ""


@dataclass(frozen=True)
class ToolOutputEvent(ScanEvent):
    """Real-time output line from a running tool subprocess."""

    plugin_name: str = ""
    line: str = ""
    is_stderr: bool = False


@dataclass(frozen=True)
class ToolFindingEvent(ScanEvent):
    """A finding detected in real-time from streaming tool output."""

    plugin_name: str = ""
    severity: str = ""
    title: str = ""
    target: str = ""


@dataclass(frozen=True)
class PipelineEvent(ScanEvent):
    """Event from the post-processing pipeline."""

    stage: str = ""  # normalize, deduplicate, fp_filter, enrich
    finding_count: int = 0
    detail: str = ""


@dataclass(frozen=True)
class ScanLifecycleEvent(ScanEvent):
    """Scan-level lifecycle events."""

    target: str = ""
    profile: str = ""
    plugin_count: int = 0
    finding_count: int = 0
    duration_seconds: float = 0.0
    error: str = ""


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

# Listener type: async callable that receives any ScanEvent subclass
Listener = Callable[[Any], Awaitable[None]]


class ScanEventBus:
    """Async event bus for scan progress events.

    Thread-safe for asyncio — all operations are coroutine-based.
    Listeners are called concurrently via asyncio.gather for each event.

    Usage:
        bus = ScanEventBus()
        bus.on(EventType.NODE_STARTED, my_handler)
        bus.on_any(my_catch_all_handler)
        await bus.emit(NodeEvent(event_type=EventType.NODE_STARTED, ...))
    """

    def __init__(self) -> None:
        self._listeners: dict[EventType, list[Listener]] = defaultdict(list)
        self._any_listeners: list[Listener] = []

    def on(self, event_type: EventType, listener: Listener) -> None:
        """Register a listener for a specific event type."""
        self._listeners[event_type].append(listener)

    def on_any(self, listener: Listener) -> None:
        """Register a listener that receives ALL events."""
        self._any_listeners.append(listener)

    def off(self, event_type: EventType, listener: Listener) -> None:
        """Remove a specific listener."""
        listeners = self._listeners.get(event_type, [])
        if listener in listeners:
            listeners.remove(listener)

    async def emit(self, event: ScanEvent) -> None:
        """Emit an event to all registered listeners.

        Listeners for the specific event type AND catch-all listeners
        are invoked concurrently. Listener exceptions are suppressed
        to prevent one bad listener from breaking the scan pipeline.
        """
        targets = list(self._listeners.get(event.event_type, []))
        targets.extend(self._any_listeners)

        if not targets:
            return

        results = await asyncio.gather(
            *(listener(event) for listener in targets),
            return_exceptions=True,
        )

        # Log but don't propagate listener errors
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Avoid importing logging at module level to keep this lightweight
                import logging

                logging.getLogger(__name__).debug(
                    "Event listener error for %s: %s", event.event_type, result
                )

    def clear(self) -> None:
        """Remove all listeners."""
        self._listeners.clear()
        self._any_listeners.clear()


# ---------------------------------------------------------------------------
# Snapshot: aggregated state for TUI rendering
# ---------------------------------------------------------------------------


@dataclass
class PluginStatus:
    """Current status of a single plugin for display purposes."""

    name: str
    state: str = "pending"  # pending, waiting, running, completed, failed, skipped, timed_out
    elapsed_seconds: float = 0.0
    finding_count: int = 0
    waiting_for: str = ""
    last_output: str = ""
    error: str = ""
    started_at: float = 0.0


@dataclass
class ScanSnapshot:
    """Aggregated scan state — consumed by the TUI to render one frame.

    The TUI reads this every ~0.5s and redraws.
    """

    target: str = ""
    profile: str = ""
    scan_id: str = ""
    started_at: float = field(default_factory=time.monotonic)

    plugins: dict[str, PluginStatus] = field(default_factory=dict)
    total_findings: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
    )
    recent_findings: list[str] = field(default_factory=list)  # Last 5 finding summaries
    pipeline_stage: str = ""  # Current post-processing stage
    pipeline_detail: str = ""

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def completed_count(self) -> int:
        return sum(
            1
            for p in self.plugins.values()
            if p.state in ("completed", "failed", "skipped", "timed_out")
        )

    @property
    def running_count(self) -> int:
        return sum(1 for p in self.plugins.values() if p.state == "running")

    @property
    def total_count(self) -> int:
        return len(self.plugins)

    @property
    def progress_fraction(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.completed_count / self.total_count


class ScanSnapshotCollector:
    """Listens to events and maintains a ScanSnapshot for TUI consumption.

    Register this as an on_any listener on the event bus.
    The TUI polls snapshot at its refresh rate.
    """

    def __init__(self) -> None:
        self.snapshot = ScanSnapshot()

    async def handle_event(self, event: ScanEvent) -> None:
        """Update snapshot from incoming event."""
        s = self.snapshot

        if isinstance(event, ScanLifecycleEvent):
            if event.event_type == EventType.SCAN_STARTED:
                s.target = event.target
                s.profile = event.profile
                s.scan_id = event.scan_id
                s.started_at = event.timestamp

        elif isinstance(event, NodeEvent):
            name = event.plugin_name
            if name not in s.plugins:
                s.plugins[name] = PluginStatus(name=name)

            ps = s.plugins[name]

            if event.event_type == EventType.NODE_QUEUED:
                ps.state = "pending"

            elif event.event_type == EventType.NODE_WAITING:
                ps.state = "waiting"
                ps.waiting_for = event.waiting_for

            elif event.event_type == EventType.NODE_STARTED:
                ps.state = "running"
                ps.started_at = event.timestamp

            elif event.event_type == EventType.NODE_PROGRESS:
                ps.finding_count = event.finding_count
                if event.detail:
                    ps.last_output = event.detail

            elif event.event_type == EventType.NODE_COMPLETED:
                ps.state = "completed"
                ps.elapsed_seconds = event.elapsed_seconds
                ps.finding_count = event.finding_count

            elif event.event_type == EventType.NODE_FAILED:
                ps.state = "failed"
                ps.elapsed_seconds = event.elapsed_seconds
                ps.error = event.error

            elif event.event_type == EventType.NODE_SKIPPED:
                ps.state = "skipped"
                ps.error = event.error

            elif event.event_type == EventType.NODE_TIMED_OUT:
                ps.state = "timed_out"
                ps.elapsed_seconds = event.elapsed_seconds

        elif isinstance(event, ToolOutputEvent):
            name = event.plugin_name
            if name in s.plugins:
                s.plugins[name].last_output = event.line[:120]

        elif isinstance(event, ToolFindingEvent):
            s.total_findings += 1
            sev = event.severity.lower()
            if sev in s.severity_counts:
                s.severity_counts[sev] += 1
            summary = f"[{event.plugin_name}] {event.severity.upper()} {event.title}"
            s.recent_findings.append(summary)
            if len(s.recent_findings) > 8:
                s.recent_findings = s.recent_findings[-8:]
            # Also update plugin finding count
            if event.plugin_name in s.plugins:
                s.plugins[event.plugin_name].finding_count += 1

        elif isinstance(event, PipelineEvent):
            s.pipeline_stage = event.stage
            s.pipeline_detail = event.detail
