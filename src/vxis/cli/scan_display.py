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

        self.phases: list[dict] = []
        self.current_phase: str | None = None
        self.current_vector: str | None = None
        self.current_reasoning: str = ""
        self.loop_mode = False
        self.loop_iteration = 0
        self.loop_max_iters = 0
        self.loop_status = ""
        self.waiting_reason = ""
        self.current_objective: str = ""       # Phase guide objective_ko
        self.current_crown_hint: str = ""      # Phase guide crown_hint_ko
        self.attack_feed: deque = deque(maxlen=6)
        self.hit_feed: deque = deque(maxlen=4)
        self.chains: dict[str, dict] = {}  # chain_id → {origin, steps, current_level}
        self.current_chain: str | None = None
        self.findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        self.total_findings = 0
        self.total_attacks = 0
        self.total_chains = 0
        self.todo_counts: dict[str, int] = {}
        self.branch_counts: dict[str, int] = {}
        self.todo_items: list[dict] = []
        self.branch_items: list[dict] = []
        self.shared_notes: list[str] = []
        self.telemetry: dict = {}
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
            if data.get("phase") == "scan_loop" or data.get("name") == "ScanAgentLoop":
                self.loop_mode = True
                self.current_phase = "Scan Loop"
                self.phases = [{
                    "id": "SL",
                    "name": "Scan Loop",
                    "status": "running",
                    "duration": 0.0,
                    "findings": 0,
                    "error": "",
                }]
                return
            self.current_phase = data["name"]
            # Store guide info for TUI display
            guide = data.get("guide", {})
            if guide:
                self.current_objective = guide.get("objective_ko", "")[:100]
                self.current_crown_hint = guide.get("crown_hint_ko", "")[:80]
            for p in self.phases:
                if p["name"] in (data.get("name") or data.get("phase") or ""):
                    p["status"] = "running"
                    break

        elif event_type == "phase_end":
            if self.loop_mode and self.phases:
                self.phases[0]["status"] = "failed" if data.get("failed") else "done"
                self.phases[0]["duration"] = data.get("duration_s", self.phases[0]["duration"])
                self.phases[0]["findings"] = data.get("total_findings", self.total_findings)
                self.phases[0]["error"] = data.get("error", "")
                self.current_phase = None
                return
            for p in self.phases:
                if p["name"] in (data.get("name") or data.get("phase") or ""):
                    p["status"] = "failed" if data.get("failed") else "done"
                    p["duration"] = data.get("duration_s", 0.0)
                    p["findings"] = data.get("new_findings", 0)
                    p["error"] = data.get("error", "")
                    break
            self.current_phase = None
            self.total_findings = data.get("total_findings", self.total_findings)
            # Severity 카운트 누계 갱신 (pipeline이 매 phase_end마다 보냄)
            sev_counts = data.get("severity_counts")
            if sev_counts:
                for k in self.findings_count:
                    if k in sev_counts:
                        self.findings_count[k] = sev_counts[k]

        elif event_type == "phase_skip":
            for p in self.phases:
                if p["name"] in (data.get("name") or data.get("phase") or ""):
                    p["status"] = "skipped"
                    break

        elif event_type == "phase_error":
            self.last_error = f"{data.get('name', '?')}: {data.get('error', '?')[:80]}"

        elif event_type == "attack":
            vector = data.get("vector_id", "?")
            method = data.get("method", "?")
            endpoint = data.get("endpoint", "?")
            _ep = endpoint[-38:] if len(endpoint) > 38 else endpoint
            self.attack_feed.append(f"[dim]▶[/dim] [cyan]{vector:<18}[/cyan] [yellow]{method:<5}[/yellow] {_ep}")
            self.total_attacks += 1
            self.current_vector = vector
            self.loop_status = f"{method} {endpoint}"[:100]

        elif event_type == "hit":
            severity = str(data.get("severity", "")).lower()
            vector = data.get("vector_id") or data.get("title") or data.get("finding_id") or "finding"
            level = data.get("level")
            if not level:
                level = {
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "informational": 1,
                }.get(severity, 1)
            conf = data.get("confidence") or severity or "reported"
            hint = (data.get("hint") or data.get("title") or "")[:35]
            level_str = f"L{level}" if level else ""
            hit_line = f"[bold red]!![/bold red] [cyan]{vector}[/cyan] {level_str} [{conf}]"
            if hint:
                hit_line += f" → [dim]{hint}[/dim]"
            self.hit_feed.append(hit_line)
            if severity in self.findings_count:
                self.findings_count[severity] += 1
            self.total_findings += 1

        elif event_type == "brain_thinking":
            self.loop_iteration = int(data.get("iteration") or self.loop_iteration or 0)
            self.loop_max_iters = int(data.get("max_iters") or self.loop_max_iters or 0)
            vectors = data.get("vectors", [])
            # 첫 벡터의 reasoning을 표시
            if vectors:
                first = vectors[0]
                self.current_vector = first.get("id", "")
                self.current_reasoning = first.get("reasoning", "")[:80]
                self.loop_status = self.current_reasoning

        elif event_type == "control_plane":
            self.loop_iteration = int(data.get("iteration") or self.loop_iteration or 0)
            self.loop_max_iters = int(data.get("max_iters") or self.loop_max_iters or 0)
            self.waiting_reason = (data.get("waiting_reason") or "")[:120]
            self.todo_counts = dict(data.get("todo_counts") or {})
            self.branch_counts = dict(data.get("branch_counts") or {})
            self.todo_items = list(data.get("todos") or [])
            self.branch_items = list(data.get("branches") or [])
            self.shared_notes = list(data.get("shared_notes") or [])
            self.telemetry = dict(data.get("telemetry") or {})
            note = (data.get("note") or "")[:100]
            if note:
                self.loop_status = note

        elif event_type == "chain_start":
            chain_id = data.get("chain_id", "?")
            ftype = data.get("finding_type", "?")
            endpoint = data.get("endpoint", "?")[-30:]
            vector = data.get("vector_id", "?")
            self.chains[chain_id] = {
                "origin_type": ftype,
                "origin_endpoint": endpoint,
                "origin_vector": vector,
                "steps": [],
                "max_level": 1,
            }
            self.current_chain = chain_id
            self.total_chains += 1

        elif event_type == "chain_step":
            chain_id = data.get("chain_id", "?")
            if chain_id in self.chains:
                step = {
                    "vector": data.get("vector_id", "?"),
                    "endpoint": data.get("endpoint", "?")[-30:],
                    "level": data.get("level", 0),
                    "reasoning": data.get("reasoning", "")[:60],
                }
                self.chains[chain_id]["steps"].append(step)
                self.chains[chain_id]["max_level"] = max(
                    self.chains[chain_id]["max_level"],
                    step["level"],
                )

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
        if self.loop_mode:
            status = self.phases[0]["status"] if self.phases else "running"
            icon = {
                "pending": "[dim]○[/dim]",
                "running": "[bold yellow]◉[/bold yellow]",
                "done": "[bold green]✓[/bold green]",
                "failed": "[bold red]✗[/bold red]",
                "skipped": "[dim]↷[/dim]",
            }.get(status, "?")
            table = Table.grid(padding=(0, 1))
            table.add_column(style="bold", width=10, no_wrap=True)
            table.add_column()
            table.add_row("Status", f"{icon} {status}")
            if self.loop_max_iters:
                table.add_row("Iteration", f"{self.loop_iteration}/{self.loop_max_iters}")
            elif self.loop_iteration:
                table.add_row("Iteration", str(self.loop_iteration))
            if self.current_vector:
                table.add_row("Focus", self.current_vector[:48])
            if self.loop_status:
                table.add_row("Latest", self.loop_status[:96])
            if self.waiting_reason:
                table.add_row("Block", self.waiting_reason[:96])
            if self.todo_counts:
                open_todos = sum(v for k, v in self.todo_counts.items() if k not in ("done", "blocked"))
                table.add_row("Todos", f"{open_todos} open / {sum(self.todo_counts.values())} total")
            if self.branch_counts:
                active_branches = sum(
                    v for k, v in self.branch_counts.items()
                    if k not in ("proven", "exhausted", "dead", "blocked")
                )
                table.add_row("Branches", f"{active_branches} active / {sum(self.branch_counts.values())} total")
            table.add_row("Findings", str(self.total_findings))
            table.add_row("Chains", str(self.total_chains))
            return Panel(
                table,
                title="[bold]Scan Loop[/bold]",
                border_style="blue",
            )

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

    def _render_brain_thinking(self) -> Panel:
        """현재 Brain이 무엇을 시도 중인지 + Phase Guide 힌트 표시."""
        content_parts = []

        # Phase Guide 정보 (새로 통합됨)
        if self.current_objective:
            content_parts.append(f"[bold yellow]🎯 목표:[/bold yellow] [italic]{self.current_objective}[/italic]")
        if self.current_crown_hint:
            content_parts.append(f"[bold red]👑 크라운:[/bold red] [dim italic]{self.current_crown_hint}[/dim italic]")

        # Brain runtime 정보
        if self.current_vector:
            content_parts.append(f"[bold cyan]Vector:[/bold cyan] {self.current_vector}")
        if self.current_reasoning:
            content_parts.append(f"[bold]Reasoning:[/bold] [italic]{self.current_reasoning}[/italic]")

        if not content_parts:
            content = "[dim]Brain analyzing target...[/dim]"
        else:
            content = "\n".join(content_parts)

        return Panel(
            content,
            title="[bold magenta]🧠 Brain Thinking[/bold magenta]",
            border_style="magenta",
        )

    def _render_attack_feed(self) -> Panel:
        lines = list(self.attack_feed) if self.attack_feed else ["[dim]waiting for attacks...[/dim]"]
        content = "\n".join(lines)
        return Panel(
            content,
            title=f"[bold]Live Attacks[/bold] [dim](total: {self.total_attacks})[/dim]",
            border_style="yellow",
        )

    def _render_control_plane(self) -> Panel:
        lines: list[str] = []

        if self.waiting_reason:
            lines.append(f"[bold yellow]Block:[/bold yellow] {self.waiting_reason}")

        if self.telemetry:
            provider = self.telemetry.get("provider") or "?"
            model = self.telemetry.get("model") or "?"
            total_tokens = int(self.telemetry.get("total_tokens") or 0)
            token_prefix = "~" if self.telemetry.get("tokens_estimated") else ""
            llm_calls = int(self.telemetry.get("llm_calls") or self.telemetry.get("calls") or 0)
            brain_decisions = int(self.telemetry.get("brain_decisions") or 0)
            cost_usd = float(self.telemetry.get("cost_usd") or 0.0)
            cost_prefix = "est. " if self.telemetry.get("cost_estimated") else ""
            lines.append(f"[bold cyan]LLM:[/bold cyan] {provider}/{model}")
            lines.append(f"[dim]{llm_calls} calls · {brain_decisions} decisions · {token_prefix}{total_tokens:,} tok[/dim]")
            lines.append(f"[dim]Cost {cost_prefix}${cost_usd:.4f}[/dim]")

        if self.todo_items:
            lines.append("[bold]Todos[/bold]")
            icons = {"pending": "○", "in_progress": "◉", "done": "✓", "blocked": "■"}
            for todo in self.todo_items[:3]:
                icon = icons.get(todo.get("status", "pending"), "•")
                title = str(todo.get("title", ""))[:44]
                lines.append(f"{icon} p{todo.get('priority', 0)} {title}")

        if self.branch_items:
            lines.append("[bold]Branches[/bold]")
            for branch in self.branch_items[:3]:
                title = str(branch.get("vector_id") or branch.get("title") or "?")[:26]
                status = str(branch.get("status") or "?")
                attempts = int(branch.get("attempts") or 0)
                last_tool = str(branch.get("last_tool") or "")[:14]
                suffix = f" via {last_tool}" if last_tool else ""
                lines.append(f"{status:<9} {title} a{attempts}{suffix}")
                next_step = str(branch.get("next_step") or "")[:68]
                if next_step:
                    lines.append(f"  [dim]next: {next_step}[/dim]")

        if self.shared_notes:
            lines.append("[bold]Notes[/bold]")
            for note in self.shared_notes[-2:]:
                lines.append(f"[dim]- {note[:70]}[/dim]")

        if not lines:
            lines = ["[dim]control plane warming up...[/dim]"]

        return Panel(
            "\n".join(lines),
            title="[bold]Control Plane[/bold]",
            border_style="cyan",
        )

    def _render_chains(self) -> Panel:
        """공격 체인 진행 상황 — 각 체인의 단계를 트리 형태로."""
        if not self.chains:
            return Panel(
                "[dim]No chains yet — chains build when findings are exploited[/dim]",
                title=f"[bold]🔗 Attack Chains[/bold] [dim]({self.total_chains})[/dim]",
                border_style="blue",
            )

        # 최근 2개 체인만 표시
        recent_chains = list(self.chains.items())[-2:]
        lines = []
        for chain_id, chain in recent_chains:
            origin = chain["origin_type"][:15]
            ep = chain["origin_endpoint"]
            max_lvl = chain["max_level"]
            level_color = {4: "bold red", 3: "red", 2: "yellow", 1: "white"}.get(max_lvl, "dim")
            lines.append(f"[{level_color}]◉[/{level_color}] [cyan]{origin}[/cyan] [dim]{ep}[/dim] [bold]L{max_lvl}[/bold]")
            for i, step in enumerate(chain["steps"][:3]):
                prefix = "└─" if i == len(chain["steps"]) - 1 else "├─"
                lvl_c = {4: "bold red", 3: "red", 2: "yellow", 1: "white"}.get(step["level"], "dim")
                lines.append(f"  {prefix} [{lvl_c}]L{step['level']}[/{lvl_c}] [cyan]{step['vector'][:14]}[/cyan] [dim]{step['endpoint']}[/dim]")
                if step.get("reasoning"):
                    lines.append(f"      [italic dim]{step['reasoning'][:50]}[/italic dim]")
            if len(chain["steps"]) > 3:
                lines.append(f"  [dim]... +{len(chain['steps']) - 3} more steps[/dim]")
        content = "\n".join(lines) if lines else "[dim]building chains...[/dim]"
        return Panel(
            content,
            title=f"[bold]🔗 Attack Chains[/bold] [dim]({self.total_chains})[/dim]",
            border_style="blue",
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
        if self.telemetry:
            total_tokens = int(self.telemetry.get("total_tokens") or 0)
            token_prefix = "~" if self.telemetry.get("tokens_estimated") else ""
            parts.append(f"[bold]Tokens:[/bold] [cyan]{token_prefix}{total_tokens:,}[/cyan]")

        return Panel(" │ ".join(parts), border_style="cyan")

    def _render(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(self._render_header(), size=9, name="header"),
            Layout(name="main"),
            Layout(self._render_footer(), size=3, name="footer"),
        )
        layout["main"].split_row(
            Layout(self._render_phases(), name="phases", ratio=2),
            Layout(name="center", ratio=3),
            Layout(name="right", ratio=2),
        )
        # Center column: Brain thinking + Attack feed + Chains
        layout["center"].split(
            Layout(self._render_brain_thinking(), size=9, name="thinking"),
            Layout(self._render_control_plane(), size=12, name="control"),
            Layout(self._render_attack_feed(), name="attacks"),
            Layout(self._render_chains(), name="chains"),
        )
        # Right column: Hits + Findings
        layout["right"].split(
            Layout(self._render_hits(), name="hits"),
            Layout(self._render_findings(), size=11, name="findings"),
        )
        return layout

    def __enter__(self):
        # Proxy renderable: Rich Live calls __rich_console__ on every refresh tick,
        # so passing this proxy makes _render() re-evaluate live (elapsed time,
        # phase status, feeds) instead of freezing the initial snapshot.
        display = self

        class _LiveProxy:
            def __rich_console__(self, console, options):  # noqa: D401
                yield display._render()

        self._live = Live(
            _LiveProxy(),
            console=self.console,
            refresh_per_second=4,
            screen=False,
            transient=False,
        )
        self._live.start()
        return self

    def __exit__(self, *args):
        if self._live:
            self._live.update(self._render())
            self._live.stop()

    def refresh(self):
        if self._live:
            self._live.update(self._render())
