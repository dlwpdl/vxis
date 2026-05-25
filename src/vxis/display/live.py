from __future__ import annotations
from datetime import datetime, timezone
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box
from ..graph.attack_graph import LivingAttackGraph
from ..graph.hypothesis import HypothesisQueue

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class CRTLiveDisplay:
    """
    VXIS Cognitive Red Team 실시간 터미널 디스플레이.
    """

    def __init__(
        self,
        target: str,
        depth: str,
        stealth: bool,
        attack_graph: LivingAttackGraph,
        hypothesis_queue: HypothesisQueue,
    ):
        self.target = target
        self.depth = depth
        self.stealth = stealth
        self.attack_graph = attack_graph
        self.hypothesis_queue = hypothesis_queue
        self._console = Console(force_terminal=True)
        self._start_time = datetime.now(timezone.utc)
        self._active_agents: dict[str, str] = {}
        self._director_status = "Initializing..."
        self._live: Live | None = None

    def update_agent(self, agent_id: str, status: str) -> None:
        self._active_agents[agent_id] = status
        if self._live:
            self._live.update(self._render())

    def update_director(self, message: str) -> None:
        self._director_status = message
        if self._live:
            self._live.update(self._render())

    def _elapsed(self) -> str:
        delta = datetime.now(timezone.utc) - self._start_time
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _render_header(self) -> Panel:
        mode = f"[bold cyan]{self.depth}[/]"
        if self.stealth:
            mode += " [bold green]| stealth[/]"
        title = f"[bold white]VXIS CRT[/] - {mode}"
        content = (
            f"[dim]Target:[/] [bold]{self.target}[/]   [dim]Elapsed:[/] [bold]{self._elapsed()}[/]"
        )
        return Panel(content, title=title, border_style="bright_blue")

    def _render_agents(self) -> Panel:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Status", width=2)
        table.add_column("Agent", width=20)
        table.add_column("State", width=12)

        for agent_id, status in list(self._active_agents.items())[-8:]:
            icon = "●" if status == "running" else "◎" if status == "spawning" else "✓"
            color = "green" if status == "running" else "yellow" if status == "spawning" else "dim"
            table.add_row(
                f"[{color}]{icon}[/]",
                f"[{color}]{agent_id}[/]",
                f"[dim]{status}[/]",
            )
        return Panel(table, title="[dim]AGENTS[/]", border_style="dim")

    def _render_graph(self) -> Panel:
        summary = self.attack_graph.summary()
        chains = self.attack_graph.find_critical_chains()

        lines = []
        for chain in chains[:3]:
            parts = [f"[bold]{n.title[:20]}[/]" for n in chain]
            lines.append(" → ".join(parts))

        if not lines:
            lines = ["[dim]No chains yet...[/]"]

        content = "\n".join(lines)
        title = f"[dim]ATTACK GRAPH[/] [dim]({summary['total_edges']} edges)[/]"
        return Panel(content, title=title, border_style="dim")

    def _render_hypotheses(self) -> Panel:
        pending = [h for h in self.hypothesis_queue._heap if h.status.value == "pending"]
        pending_sorted = sorted(pending, key=lambda h: h.priority_score, reverse=True)

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Score", width=6)
        table.add_column("Hypothesis", width=28)
        table.add_column("Agent", width=14)

        for h in pending_sorted[:5]:
            score_pct = int(h.priority_score * 100)
            table.add_row(
                f"[cyan]{score_pct}%[/]",
                h.title[:28],
                f"[dim]{h.suggested_agent}[/]",
            )
        return Panel(table, title="[dim]HYPOTHESIS QUEUE[/]", border_style="dim")

    def _render_findings(self) -> Panel:
        summary = self.attack_graph.summary()
        lines = [
            f"[bold red]CRITICAL  {summary['critical']:>4}[/]",
            f"[red]HIGH      {summary['high']:>4}[/]",
            f"[yellow]MEDIUM    {summary['medium']:>4}[/]",
            f"[cyan]LOW       {summary['low']:>4}[/]",
            "",
            f"[dim]CHAINS    {summary['total_chains']:>4}[/]",
        ]
        return Panel("\n".join(lines), title="[dim]FINDINGS[/]", border_style="dim")

    def _render_director(self) -> Panel:
        return Panel(
            f"[bold yellow]DIRECTOR:[/] {self._director_status}",
            border_style="bright_blue",
        )

    def _render(self):
        from rich.layout import Layout

        layout = Layout()
        layout.split_column(
            Layout(self._render_header(), size=3),
            Layout(name="middle"),
            Layout(self._render_director(), size=3),
        )
        layout["middle"].split_row(
            Layout(self._render_agents(), ratio=2),
            Layout(self._render_graph(), ratio=3),
            Layout(self._render_hypotheses(), ratio=3),
            Layout(self._render_findings(), ratio=2),
        )
        return layout

    def start(self) -> "CRTLiveDisplay":
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=2,
            screen=False,
        )
        self._live.start()
        return self

    def stop(self) -> None:
        if self._live:
            self._live.stop()

    def __enter__(self) -> "CRTLiveDisplay":
        return self.start()

    def __exit__(self, *args) -> None:
        self.stop()
