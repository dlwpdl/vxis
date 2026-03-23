"""Rich Live TUI for real-time scan progress display.

Renders a continuously-updating terminal dashboard showing:
- Pipeline progress bar with plugin states
- Per-plugin status table (state, elapsed, findings, last output)
- Real-time finding ticker with severity counts
- Live log of recent findings

Designed to be driven by ScanSnapshot from the event system.
"""

from __future__ import annotations

import time

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from vxis.core.events import PluginStatus, ScanSnapshot

# ---------------------------------------------------------------------------
# State icons and colors
# ---------------------------------------------------------------------------

STATE_DISPLAY = {
    "pending":   ("○", "dim"),
    "waiting":   ("◌", "yellow"),
    "running":   ("▶", "bold cyan"),
    "completed": ("✓", "green"),
    "failed":    ("✗", "bold red"),
    "skipped":   ("—", "dim"),
    "timed_out": ("⏱", "yellow"),
}

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim",
}


# ---------------------------------------------------------------------------
# TUI renderer
# ---------------------------------------------------------------------------


def build_scan_display(snapshot: ScanSnapshot) -> Group:
    """Build the full TUI layout from a ScanSnapshot.

    Returns a Rich Group that can be passed to Live.update().
    """
    return Group(
        _build_header(snapshot),
        _build_plugin_table(snapshot),
        _build_findings_panel(snapshot),
        _build_ticker(snapshot),
    )


def _build_header(s: ScanSnapshot) -> Panel:
    """Top bar: target, profile, progress, elapsed time."""
    elapsed = s.elapsed_seconds
    mins, secs = divmod(int(elapsed), 60)

    # Progress bar text
    completed = s.completed_count
    total = s.total_count
    running = s.running_count
    pct = int(s.progress_fraction * 100)

    bar_filled = int(s.progress_fraction * 30)
    bar_empty = 30 - bar_filled
    bar = f"[green]{'█' * bar_filled}[/green][dim]{'░' * bar_empty}[/dim]"

    header = Text.from_markup(
        f"  [bold cyan]{s.target}[/bold cyan]  |  "
        f"[yellow]{s.profile}[/yellow]  |  "
        f"{bar} {pct}%  |  "
        f"[bold]{completed}[/bold]/{total} plugins  |  "
        f"[cyan]{running}[/cyan] running  |  "
        f"[dim]{mins:02d}:{secs:02d}[/dim]"
    )

    # Pipeline stage indicator
    if s.pipeline_stage:
        header.append(f"  |  [magenta]{s.pipeline_stage}[/magenta]")

    return Panel(header, border_style="cyan", padding=(0, 1))


def _build_plugin_table(s: ScanSnapshot) -> Table:
    """Per-plugin status table."""
    table = Table(
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("", width=2, no_wrap=True)  # State icon
    table.add_column("Plugin", style="bold", no_wrap=True, min_width=14)
    table.add_column("State", no_wrap=True, min_width=10)
    table.add_column("Time", justify="right", no_wrap=True, width=8)
    table.add_column("Findings", justify="right", no_wrap=True, width=9)
    table.add_column("Detail", ratio=1)

    # Sort: running first, then waiting, then pending, then completed
    order = {"running": 0, "waiting": 1, "pending": 2, "completed": 3, "failed": 4, "skipped": 5, "timed_out": 6}
    sorted_plugins = sorted(
        s.plugins.values(),
        key=lambda p: (order.get(p.state, 9), p.name),
    )

    for ps in sorted_plugins:
        icon, style = STATE_DISPLAY.get(ps.state, ("?", ""))

        # Elapsed time
        if ps.state == "running" and ps.started_at > 0:
            elapsed = time.monotonic() - ps.started_at
            time_str = f"{elapsed:.1f}s"
        elif ps.elapsed_seconds > 0:
            time_str = f"{ps.elapsed_seconds:.1f}s"
        else:
            time_str = "—"

        # Finding count
        finding_str = str(ps.finding_count) if ps.finding_count > 0 else "—"

        # Detail column
        if ps.state == "waiting" and ps.waiting_for:
            detail = f"[dim]waiting → {ps.waiting_for}[/dim]"
        elif ps.state == "running" and ps.last_output:
            detail = f"[dim]{ps.last_output[:60]}[/dim]"
        elif ps.error:
            detail = f"[red]{ps.error[:60]}[/red]"
        else:
            detail = ""

        table.add_row(
            f"[{style}]{icon}[/{style}]",
            ps.name,
            f"[{style}]{ps.state}[/{style}]",
            time_str,
            finding_str,
            detail,
        )

    return table


def _build_findings_panel(s: ScanSnapshot) -> Panel:
    """Severity count summary bar."""
    parts = []
    for sev in ("critical", "high", "medium", "low", "informational"):
        count = s.severity_counts.get(sev, 0)
        style = SEVERITY_STYLES.get(sev, "")
        label = sev[:4].upper()
        if count > 0:
            parts.append(f"[{style}]{label}: {count}[/{style}]")
        else:
            parts.append(f"[dim]{label}: 0[/dim]")

    total = s.total_findings
    bar_text = "  ".join(parts) + f"    [bold]Total: {total}[/bold]"

    return Panel(
        Text.from_markup(f"  {bar_text}"),
        title="[bold]Findings[/bold]",
        border_style="green" if total > 0 else "dim",
        padding=(0, 1),
    )


def _build_ticker(s: ScanSnapshot) -> Panel:
    """Recent finding ticker — shows last few discoveries."""
    if not s.recent_findings:
        content = Text("[dim]  Waiting for findings...[/dim]")
        content = Text.from_markup("  [dim]Waiting for findings...[/dim]")
    else:
        lines = []
        for entry in s.recent_findings[-5:]:
            lines.append(f"  {entry}")
        content = Text.from_markup("\n".join(lines))

    return Panel(
        content,
        title="[bold]Live Feed[/bold]",
        border_style="dim",
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Live display manager
# ---------------------------------------------------------------------------


class ScanLiveDisplay:
    """Manages a Rich Live context for continuous TUI updates.

    Usage:
        display = ScanLiveDisplay(console)
        with display:
            # In event loop, periodically call:
            display.update(snapshot)
    """

    def __init__(self, console: Console, refresh_rate: float = 4.0) -> None:
        self._console = console
        self._live = Live(
            "",
            console=console,
            refresh_per_second=refresh_rate,
            transient=False,
        )

    def __enter__(self) -> ScanLiveDisplay:
        self._live.__enter__()
        return self

    def __exit__(self, *args) -> None:
        self._live.__exit__(*args)

    def update(self, snapshot: ScanSnapshot) -> None:
        """Redraw the TUI with the latest snapshot."""
        self._live.update(build_scan_display(snapshot))
