"""Rich Live display for vxis scan — real-time phase progress + attack feed."""

from __future__ import annotations

import time
from collections import deque

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text


class ScanLiveDisplay:
    """실시간 스캔 진행 상황 표시.

    레이아웃:
    ┌──────────────── VXIS Scan ────────────────┐
    │ Target: ... | Brain: ... | Ghost: ...     │
    ├───────────── Phases (14) ────────────────┤
    │ ✓ Phase 0: Foundation          (0.1s)    │
    │ ✓ Phase 1: Director            (0.2s)    │
    │ ◉ Phase 4: CPR      [running]            │
    │ ○ Phase 15: Digital Twin                 │
    │   ...                                    │
    ├──────────── Live Attack Feed ────────────┤
    │ ▶ WEB-SQLI-001 POST /login               │
    │ !! HIT WEB-SQLI-001 L3 [high]            │
    ├──────────── Findings (3) ────────────────┤
    │ Critical: 1 | High: 1 | Medium: 1        │
    └─── Elapsed: 42.3s ───────────────────────┘
    """

    def __init__(self, console, target: str, profile: str, brain: str, ghost: bool, version: str):
        self.console = console
        self.target = target
        self.profile = profile
        self.brain = brain
        self.ghost = ghost
        self.version = version

        self.phases: list[dict] = []  # [{id, name, status, duration, findings}]
        self.current_phase: str | None = None
        self.attack_feed: deque = deque(maxlen=8)  # recent 8 attacks
        self.hit_feed: deque = deque(maxlen=5)     # recent 5 hits
        self.findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        self.total_findings = 0
        self.total_attacks = 0
        self.start_time = time.monotonic()
        self.score: dict | None = None
        self.last_error: str | None = None

        self._live: Live | None = None

    def init_phases(self, phase_list: list):
        """Registry에서 Phase 목록 초기화."""
        for p in phase_list:
            self.phases.append({
                "id": p.id,
                "name": p.name,
                "status": "pending",   # pending | running | done | failed | skipped
                "duration": 0.0,
                "findings": 0,
                "error": "",
            })

    def handle_event(self, event_type: str, data: dict) -> None:
        """Pipeline이 emit한 event 처리."""
        if event_type == "phase_start":
            self.current_phase = data["name"]
            for p in self.phases:
                if p["name"] in data["name"]:
                    p["status"] = "running"
                    break

        elif event_type == "phase_end":
            for p in self.phases:
                if p["name"] in data["name"]:
                    p["status"] = "failed" if data.get("failed") else "done"
                    p["duration"] = data.get("duration_s", 0.0)
                    p["findings"] = data.get("new_findings", 0)
                    p["error"] = data.get("error", "")
                    break
            self.current_phase = None
            self.total_findings = data.get("total_findings", self.total_findings)

        elif event_type == "phase_skip":
            for p in self.phases:
                if p["name"] in data["name"]:
                    p["status"] = "skipped"
                    break

        elif event_type == "phase_error":
            self.last_error = f"{data.get('name', '?')}: {data.get('error', '?')[:80]}"

        elif event_type == "attack":
            vector = data.get("vector_id", "?")
            method = data.get("method", "?")
            endpoint = data.get("endpoint", "?")
            _ep = endpoint[-40:] if len(endpoint) > 40 else endpoint
            self.attack_feed.append(f"[dim]▶[/dim] [cyan]{vector:<18}[/cyan] [yellow]{method:<5}[/yellow] {_ep}")
            self.total_attacks += 1

        elif event_type == "hit":
            vector = data.get("vector_id", "?")
            level = data.get("level")
            conf = data.get("confidence", "")
            hint = data.get("hint", "")[:40]
            level_str = f"L{level}" if level else ""
            hit_line = f"[bold red]!! HIT[/bold red] [cyan]{vector}[/cyan] {level_str} [{conf}]"
            if hint:
                hit_line += f" → [dim]{hint}[/dim]"
            self.hit_feed.append(hit_line)

        elif event_type == "score":
            self.score = data

        elif event_type == "error":
            self.last_error = f"{data.get('stage', '?')}: {data.get('error', '?')[:80]}"

    # ── Renderables ───────────────────────────────────────────

    def _render_header(self) -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold", no_wrap=True)
        table.add_column()
        _pstyle = {"stealth": "yellow", "standard": "green", "aggressive": "red"}.get(self.profile, "white")
        table.add_row("Target:", f"[cyan]{self.target}[/cyan]")
        table.add_row("Profile:", f"[{_pstyle}]{self.profile}[/{_pstyle}]")
        table.add_row("Brain:", f"[green]{self.brain}[/green]")
        table.add_row("Ghost:", "[magenta]ON[/magenta]" if self.ghost else "[dim]OFF[/dim]")
        table.add_row("Version:", f"v{self.version}")
        return Panel(table, title="[bold cyan]VXIS Scan[/bold cyan]", border_style="cyan")

    def _render_phases(self) -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(width=3)  # status icon
        table.add_column(width=6)  # phase ID
        table.add_column()         # name
        table.add_column(justify="right", width=8)  # duration
        table.add_column(justify="right", width=8)  # findings

        for p in self.phases:
            icon = {
                "pending": "[dim]○[/dim]",
                "running": "[bold yellow]◉[/bold yellow]",
                "done":    "[bold green]✓[/bold green]",
                "failed":  "[bold red]✗[/bold red]",
                "skipped": "[dim]↷[/dim]",
            }.get(p["status"], "?")
            name_style = {
                "running": "bold yellow",
                "done":    "green",
                "failed":  "red",
                "skipped": "dim",
                "pending": "dim",
            }.get(p["status"], "")
            name = p["name"][:40]
            duration = f"{p['duration']:.1f}s" if p["duration"] else ""
            findings = f"+{p['findings']}" if p["findings"] else ""
            findings_style = "green" if p["findings"] else "dim"
            table.add_row(
                icon,
                f"P{p['id']}",
                f"[{name_style}]{name}[/{name_style}]" if name_style else name,
                f"[dim]{duration}[/dim]",
                f"[{findings_style}]{findings}[/{findings_style}]",
            )
        done = sum(1 for p in self.phases if p["status"] in ("done", "skipped"))
        return Panel(
            table,
            title=f"[bold]Phases[/bold] [dim]({done}/{len(self.phases)})[/dim]",
            border_style="blue",
        )

    def _render_attack_feed(self) -> Panel:
        lines = list(self.attack_feed) if self.attack_feed else ["[dim]waiting for attacks...[/dim]"]
        content = "\n".join(lines)
        return Panel(
            content,
            title=f"[bold]Live Attacks[/bold] [dim](total: {self.total_attacks})[/dim]",
            border_style="yellow",
        )

    def _render_hits(self) -> Panel:
        lines = list(self.hit_feed) if self.hit_feed else ["[dim]no hits yet[/dim]"]
        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold red]Recent Hits[/bold red]",
            border_style="red",
        )

    def _render_findings(self) -> Panel:
        # Update counts from phases
        sev_table = Table.grid(padding=(0, 2))
        sev_table.add_column(style="bold")
        sev_table.add_column(justify="right")

        styles = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "informational": "dim"}
        labels = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}

        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = self.findings_count.get(sev, 0)
            style = styles[sev]
            sev_table.add_row(f"[{style}]{labels[sev]}[/{style}]", f"[{style}]{count}[/{style}]")

        sev_table.add_row("", "")
        sev_table.add_row("[bold]Total[/bold]", f"[bold cyan]{self.total_findings}[/bold cyan]")

        return Panel(
            sev_table,
            title=f"[bold]Findings[/bold]",
            border_style="green",
        )

    def _render_footer(self) -> Panel:
        elapsed = time.monotonic() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        time_str = f"{mins}m {secs}s" if mins else f"{secs}s"

        parts = [f"[bold]Elapsed:[/bold] [cyan]{time_str}[/cyan]"]
        if self.current_phase:
            parts.append(f"[bold]Current:[/bold] [yellow]{self.current_phase[:50]}[/yellow]")
        if self.score:
            parts.append(f"[bold]Score:[/bold] [cyan]{self.score['total']:.0f}/1000[/cyan] [{self.score['grade']}]")
        if self.last_error:
            parts.append(f"[bold red]Error:[/bold red] [dim]{self.last_error[:60]}[/dim]")

        return Panel(" │ ".join(parts), border_style="cyan")

    def _render(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(self._render_header(), size=9, name="header"),
            Layout(name="main"),
            Layout(self._render_footer(), size=3, name="footer"),
        )
        layout["main"].split_row(
            Layout(self._render_phases(), name="phases"),
            Layout(name="right"),
        )
        layout["right"].split(
            Layout(self._render_attack_feed(), name="attacks"),
            Layout(self._render_hits(), name="hits"),
            Layout(self._render_findings(), size=11, name="findings"),
        )
        return layout

    def __enter__(self):
        self._live = Live(self._render(), console=self.console, refresh_per_second=4, screen=False)
        self._live.start()
        return self

    def __exit__(self, *args):
        if self._live:
            self._live.update(self._render())
            self._live.stop()

    def refresh(self):
        if self._live:
            self._live.update(self._render())
