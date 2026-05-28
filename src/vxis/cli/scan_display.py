"""Rich Live display for vxis scan — real-time phase progress + attack feed."""

from __future__ import annotations

import time
from collections import deque

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


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
        self.current_objective: str = ""  # Phase guide objective_ko
        self.current_crown_hint: str = ""  # Phase guide crown_hint_ko
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
        self.review_items: list[dict] = []
        self.chain_candidates: list[dict] = []
        self.blocking_branches: list[dict] = []
        self.campaign_groups: list[dict] = []
        self.focus_campaign: dict | None = None
        self.memory_directives: list[str] = []
        self.focus_branch: dict | None = None
        self.recent_attempts: list[dict] = []
        self.agent_items: list[dict] = []
        self.sdk_runtime: dict = {}
        self.shared_notes: list[str] = []
        self.telemetry: dict = {}
        self.proxy: dict = {}
        self.ghost_runtime: dict = {}
        self.egress_contract: dict = {}
        self.start_time = time.monotonic()
        self.score: dict | None = None
        self.last_error: str | None = None

        self._live: Live | None = None

    def init_phases(self, phase_list: list):
        """Registry에서 Phase 목록 초기화."""
        for p in phase_list:
            self.phases.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "status": "pending",  # pending | running | done | failed | skipped
                    "duration": 0.0,
                    "findings": 0,
                    "error": "",
                }
            )

    def handle_event(self, event_type: str, data: dict) -> None:
        """Pipeline이 emit한 event 처리."""
        if event_type == "phase_start":
            if data.get("phase") == "scan_loop" or data.get("name") == "ScanAgentLoop":
                self.loop_mode = True
                self.current_phase = "Scan Loop"
                self.phases = [
                    {
                        "id": "SL",
                        "name": "Scan Loop",
                        "status": "running",
                        "duration": 0.0,
                        "findings": 0,
                        "error": "",
                    }
                ]
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
            self.attack_feed.append(
                f"[dim]▶[/dim] [cyan]{vector:<18}[/cyan] [yellow]{method:<5}[/yellow] {_ep}"
            )
            self.total_attacks += 1
            self.current_vector = vector
            self.loop_status = f"{method} {endpoint}"[:100]

        elif event_type == "hit":
            severity = str(data.get("severity", "")).lower()
            vector = (
                data.get("vector_id") or data.get("title") or data.get("finding_id") or "finding"
            )
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
            self.review_items = list(data.get("reviews") or [])
            self.chain_candidates = list(data.get("chain_candidates") or [])
            self.blocking_branches = list(data.get("blocking_branches") or [])
            self.campaign_groups = list(data.get("campaign_groups") or [])
            self.focus_campaign = data.get("focus_campaign") or None
            self.memory_directives = list(data.get("memory_directives") or [])
            self.focus_branch = data.get("focus_branch") or None
            self.recent_attempts = list(data.get("recent_attempts") or [])
            self.agent_items = list(data.get("agents") or [])
            self.sdk_runtime = dict(data.get("sdk_runtime") or {})
            self.shared_notes = list(data.get("shared_notes") or [])
            self.telemetry = dict(data.get("telemetry") or {})
            self.proxy = dict(data.get("proxy") or {})
            self.ghost_runtime = dict(data.get("ghost") or {})
            self.egress_contract = dict(data.get("egress_contract") or {})
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
                "finding_ids": list(data.get("finding_ids") or []),
                "source_title": str(data.get("source_title") or "")[:60],
                "rationale": str(data.get("rationale") or "")[:90],
                "crown_jewel": str(data.get("crown_jewel") or "")[:70],
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
                    "title": str(data.get("title") or "")[:60],
                    "severity": str(data.get("severity") or ""),
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
        _pstyle = {"stealth": "yellow", "standard": "green", "aggressive": "red"}.get(
            self.profile, "white"
        )
        table.add_row("Target:", f"[cyan]{self.target}[/cyan]")
        table.add_row("Profile:", f"[{_pstyle}]{self.profile}[/{_pstyle}]")
        table.add_row("Brain:", f"[green]{self.brain}[/green]")
        runtime = self._runtime_summary()
        if runtime:
            table.add_row("LLM:", runtime)
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
                open_todos = sum(
                    v for k, v in self.todo_counts.items() if k not in ("done", "blocked")
                )
                table.add_row(
                    "Todos", f"{open_todos} open / {sum(self.todo_counts.values())} total"
                )
            if self.branch_counts:
                active_branches = sum(
                    v
                    for k, v in self.branch_counts.items()
                    if k not in ("proven", "exhausted", "dead", "blocked")
                )
                table.add_row(
                    "Branches",
                    f"{active_branches} active / {sum(self.branch_counts.values())} total",
                )
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
        table.add_column()  # name
        table.add_column(justify="right", width=8)  # duration
        table.add_column(justify="right", width=8)  # findings

        for p in self.phases:
            icon = {
                "pending": "[dim]○[/dim]",
                "running": "[bold yellow]◉[/bold yellow]",
                "done": "[bold green]✓[/bold green]",
                "failed": "[bold red]✗[/bold red]",
                "skipped": "[dim]↷[/dim]",
            }.get(p["status"], "?")
            name_style = {
                "running": "bold yellow",
                "done": "green",
                "failed": "red",
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

        runtime = self._runtime_summary()
        if runtime:
            content_parts.append(f"[bold cyan]LLM Runtime:[/bold cyan] {runtime}")

        # Phase Guide 정보 (새로 통합됨)
        if self.current_objective:
            content_parts.append(
                f"[bold yellow]🎯 목표:[/bold yellow] [italic]{self.current_objective}[/italic]"
            )
        if self.current_crown_hint:
            content_parts.append(
                f"[bold red]👑 크라운:[/bold red] [dim italic]{self.current_crown_hint}[/dim italic]"
            )

        # Brain runtime 정보
        if self.current_vector:
            content_parts.append(f"[bold cyan]Vector:[/bold cyan] {self.current_vector}")
        if self.current_reasoning:
            content_parts.append(
                f"[bold]Reasoning:[/bold] [italic]{self.current_reasoning}[/italic]"
            )

        if not content_parts:
            content = "[dim]Brain analyzing target...[/dim]"
        else:
            content = "\n".join(content_parts)

        return Panel(
            content,
            title="[bold magenta]🧠 Brain Thinking[/bold magenta]",
            border_style="magenta",
        )

    def _runtime_summary(self) -> str:
        if not self.telemetry:
            return ""
        provider = str(self.telemetry.get("provider") or "?").strip()
        model = str(self.telemetry.get("model") or "?").strip()
        base_url = str(self.telemetry.get("base_url") or "").strip()
        profile = str(self.telemetry.get("discipline_profile") or "").strip()
        runtime = f"[green]{provider}[/green]/[cyan]{model}[/cyan]"
        if profile:
            runtime += f" [magenta]{profile}[/magenta]"
        if base_url:
            runtime += f" [dim]@ {base_url[:42]}[/dim]"
        return runtime

    def _render_attack_feed(self) -> Panel:
        lines = (
            list(self.attack_feed) if self.attack_feed else ["[dim]waiting for attacks...[/dim]"]
        )
        content = "\n".join(lines)
        return Panel(
            content,
            title=f"[bold]Live Attacks[/bold] [dim](total: {self.total_attacks})[/dim]",
            border_style="yellow",
        )

    def _render_agent_monitor(self) -> Panel:
        """Crew monitor: active delegated agents, evidence, and next action."""
        if not self.agent_items:
            return Panel(
                "[dim]no delegated agents yet[/dim]\n[dim]agent_graph workers appear here[/dim]",
                title="[bold]Agents[/bold] [dim](0)[/dim]",
                border_style="bright_black",
            )

        agents = sorted(
            self.agent_items,
            key=lambda item: (
                str(item.get("status") or "") not in {"running", "waiting"},
                str(item.get("created_at") or ""),
                str(item.get("id") or ""),
            ),
        )
        active = sum(
            1 for item in agents if str(item.get("status") or "") in {"running", "waiting"}
        )
        selected = self._selected_agent(agents)
        lines: list[str] = []
        for agent in agents[:5]:
            agent_id = str(agent.get("id") or "?")
            status = str(agent.get("status") or "?")
            role = str(agent.get("role") or "worker")
            runs = int(agent.get("execution_count") or 0)
            skills = ",".join(str(skill) for skill in list(agent.get("skills") or [])[:2])
            marker = ">" if selected and agent_id == str(selected.get("id") or "") else " "
            style = {
                "running": "yellow",
                "waiting": "cyan",
                "finished": "green",
                "blocked": "red",
            }.get(status, "white")
            skill_text = f" [{skills}]" if skills else ""
            lines.append(
                f"{marker} [{style}]{agent_id}[/{style}] {status:<8} {role} r{runs}{skill_text}"
            )

        if selected:
            lines.append("")
            lines.extend(self._agent_detail_lines(selected))

        return Panel(
            "\n".join(lines),
            title=f"[bold]Agents[/bold] [dim]({active} active/{len(agents)} total)[/dim]",
            border_style="magenta",
        )

    def _selected_agent(self, agents: list[dict]) -> dict | None:
        for agent in agents:
            if str(agent.get("status") or "") in {"running", "waiting"}:
                return agent
        return agents[0] if agents else None

    def _agent_detail_lines(self, agent: dict) -> list[str]:
        lines: list[str] = []
        task = self._short(agent.get("task"), 82)
        result = self._short(agent.get("result"), 82)
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        escalation = agent.get("escalation") if isinstance(agent.get("escalation"), dict) else {}
        if task:
            lines.append(f"[bold]task[/bold] {task}")
        if envelope:
            objective = self._short(envelope.get("objective"), 84)
            target_surface = self._short(envelope.get("target_surface"), 24)
            allowed_tools = ",".join(
                str(item) for item in list(envelope.get("allowed_tools") or [])[:4]
            )
            expected_artifact = self._short(envelope.get("expected_artifact"), 88)
            stop_condition = self._short(envelope.get("stop_condition"), 88)
            escalation_trigger = self._short(envelope.get("escalation_trigger"), 88)
            lines.append("[bold cyan]contract[/bold cyan]")
            if objective:
                lines.append(f"[dim]objective:[/dim] {objective}")
            if target_surface:
                lines.append(f"[dim]surface:[/dim] {target_surface}")
            if allowed_tools:
                lines.append(f"[dim]tools:[/dim] {allowed_tools}")
            if expected_artifact:
                lines.append(f"[dim]expect:[/dim] {expected_artifact}")
            if stop_condition:
                lines.append(f"[dim]stop:[/dim] {stop_condition}")
            if escalation_trigger:
                lines.append(f"[dim]escalate on:[/dim] {escalation_trigger}")
        latest = self._latest_agent_execution(agent)
        if latest:
            verdict = "ok" if latest.get("ok") else "fail"
            tool = self._short(latest.get("tool") or "child", 18)
            summary = self._short(latest.get("summary"), 86)
            lines.append(f"[bold]last[/bold] {tool} {verdict}: {summary}")
        sdk_runtime = (
            agent.get("sdk_runtime") if isinstance(agent.get("sdk_runtime"), dict) else {}
        )
        if sdk_runtime:
            lines.extend(self._agent_sdk_runtime_lines(sdk_runtime))
        if result_package:
            attempted_tool = self._short(result_package.get("attempted_tool"), 18)
            raw_evidence = self._short(result_package.get("raw_evidence_summary"), 86)
            control_result = self._short(result_package.get("control_result"), 86)
            delta = self._short(result_package.get("observed_delta"), 86)
            verdict_guess = self._short(result_package.get("verdict_guess"), 42)
            recommended = self._short(result_package.get("recommended_next_step"), 92)
            evidence_artifact = (
                result_package.get("evidence_artifact")
                if isinstance(result_package.get("evidence_artifact"), dict)
                else {}
            )
            lines.append("[bold green]artifact[/bold green]")
            if attempted_tool:
                lines.append(f"[dim]tool:[/dim] {attempted_tool}")
            if evidence_artifact:
                proof_state = "valid" if evidence_artifact.get("valid") else "invalid"
                source = self._short(evidence_artifact.get("source"), 24)
                missing = ",".join(
                    str(item) for item in list(evidence_artifact.get("missing_fields") or [])[:6]
                )
                target = self._short(evidence_artifact.get("target"), 64)
                label = f"{proof_state} ({source})" if source else proof_state
                lines.append(f"[dim]proof:[/dim] {label}")
                if missing:
                    lines.append(f"[dim]missing:[/dim] {self._short(missing, 72)}")
                if target:
                    lines.append(f"[dim]target:[/dim] {target}")
            if raw_evidence:
                lines.append(f"[dim]evidence:[/dim] {raw_evidence}")
            if control_result:
                lines.append(f"[dim]control:[/dim] {control_result}")
            if delta:
                lines.append(f"[dim]delta:[/dim] {delta}")
            if verdict_guess:
                lines.append(f"[dim]worker guess:[/dim] {verdict_guess}")
            if recommended:
                lines.append(f"[dim]next artifact step:[/dim] {recommended}")
        if result:
            lines.append(f"[bold]result[/bold] {result}")
        if escalation:
            status = self._short(escalation.get("status"), 22)
            reason = self._short(escalation.get("reason"), 92)
            owner = self._short(escalation.get("recommended_owner"), 24)
            lines.append("[bold red]escalation[/bold red]")
            if status:
                lines.append(f"[dim]state:[/dim] {status}")
            if reason:
                lines.append(f"[dim]reason:[/dim] {reason}")
            if owner:
                lines.append(f"[dim]owner:[/dim] {owner}")
        next_step = self._agent_next_action_hint(agent)
        if next_step:
            lines.append(f"[bold cyan]next[/bold cyan] {next_step}")
        messages = list(agent.get("messages") or [])
        if messages:
            lines.append("[bold]msgs[/bold]")
            for msg in messages[-2:]:
                sender = self._short(msg.get("sender"), 14)
                body = self._short(msg.get("body"), 78)
                lines.append(f"[dim]{sender}:[/dim] {body}")
        skill_context = str(agent.get("skill_context") or "")
        action_line = next(
            (
                line.strip()
                for line in skill_context.splitlines()
                if line.strip().startswith("action:")
            ),
            "",
        )
        if action_line:
            lines.append(f"[dim]{self._short(action_line, 92)}[/dim]")
        return lines

    def _agent_sdk_runtime_lines(self, sdk_runtime: dict) -> list[str]:
        lines: list[str] = ["[bold magenta]sdk session[/bold magenta]"]
        record = sdk_runtime.get("agent") if isinstance(sdk_runtime.get("agent"), dict) else {}
        pending = int(record.get("pending_count") or 0)
        status = self._short(record.get("status"), 18)
        run_dir = self._short(sdk_runtime.get("run_dir"), 56)
        if status or pending:
            lines.append(f"[dim]runtime:[/dim] {status or '?'} pending={pending}")
        if run_dir:
            lines.append(f"[dim]run:[/dim] {run_dir}")
        events = list(sdk_runtime.get("events") or [])
        if events:
            labels = [
                self._short(event.get("event_type"), 22)
                for event in events[-4:]
                if isinstance(event, dict)
            ]
            if labels:
                lines.append(f"[dim]events:[/dim] {', '.join(labels)}")
        session_items = list(sdk_runtime.get("session_items") or [])
        if session_items:
            lines.append("[bold]session tail[/bold]")
            for item in session_items[-2:]:
                if not isinstance(item, dict):
                    continue
                role = self._short(item.get("role"), 12)
                content = self._short(item.get("content"), 86)
                lines.append(f"[dim]{role}:[/dim] {content}")
        return lines

    def _agent_next_action_hint(self, agent: dict) -> str:
        status = str(agent.get("status") or "")
        agent_id = str(agent.get("id") or "?")
        latest = self._latest_agent_execution(agent)
        result = str(agent.get("result") or "")
        if status in {"running", "waiting"}:
            if latest and latest.get("ok"):
                return f"finish {agent_id} with concrete result, or send narrower instruction"
            return f"run {agent_id} or send narrower instruction"
        lowered = result.lower()
        positive = any(
            token in lowered
            for token in ("confirmed", "vulnerable", "token", "admin", "sqli", "idor")
        )
        clean = any(
            token in lowered for token in ("clean", "not vulnerable", "no issue", "blocked")
        )
        if positive and not clean:
            return "crown-chain: create/run post_exploit_worker; verify impact before finish"
        return "use result to update branch/report, or mark exhausted"

    @staticmethod
    def _latest_agent_execution(agent: dict) -> dict | None:
        executions = agent.get("executions")
        if not isinstance(executions, list) or not executions:
            return None
        latest = executions[-1]
        return latest if isinstance(latest, dict) else None

    @staticmethod
    def _short(value: object, limit: int) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 3)].rstrip() + "..."

    def _render_control_plane(self) -> Panel:
        lines: list[str] = []

        if self.waiting_reason:
            lines.append(f"[bold yellow]Block:[/bold yellow] {self.waiting_reason}")

        if self.telemetry:
            provider = self.telemetry.get("provider") or "?"
            model = self.telemetry.get("model") or "?"
            profile = self.telemetry.get("discipline_profile") or "?"
            total_tokens = int(self.telemetry.get("total_tokens") or 0)
            token_prefix = "~" if self.telemetry.get("tokens_estimated") else ""
            llm_calls = int(self.telemetry.get("llm_calls") or self.telemetry.get("calls") or 0)
            brain_decisions = int(self.telemetry.get("brain_decisions") or 0)
            cost_usd = float(self.telemetry.get("cost_usd") or 0.0)
            cost_prefix = "est. " if self.telemetry.get("cost_estimated") else ""
            lines.append(f"[bold cyan]LLM:[/bold cyan] {provider}/{model}")
            lines.append(f"[dim]discipline {profile}[/dim]")
            lines.append(
                f"[dim]{llm_calls} calls · {brain_decisions} decisions · {token_prefix}{total_tokens:,} tok[/dim]"
            )
            lines.append(f"[dim]Cost {cost_prefix}${cost_usd:.4f}[/dim]")
            memory_compression = self.telemetry.get("memory_compression") or {}
            compress_triggered = int(memory_compression.get("triggered") or 0)
            tokens_saved = int(memory_compression.get("total_tokens_saved") or 0)
            if compress_triggered > 0 or tokens_saved > 0:
                lines.append(
                    f"[dim]compress {compress_triggered}x · save ~{tokens_saved:,} tok[/dim]"
                )

        if self.proxy:
            backend = self.proxy.get("backend") or "disabled"
            running = bool(self.proxy.get("running"))
            flow_count = int(self.proxy.get("flow_count") or 0)
            auth_flows = int(self.proxy.get("auth_flow_count") or 0)
            proxy_url = str(self.proxy.get("proxy_url") or "")[:52]
            state = "running" if running else "stopped"
            lines.append("[bold]Proxy[/bold]")
            lines.append(f"{backend} {state} · {flow_count} flows · {auth_flows} auth")
            if proxy_url:
                lines.append(f"[dim]{proxy_url}[/dim]")
            last_error = str(self.proxy.get("last_error") or "")[:70]
            if last_error:
                lines.append(f"[dim]err: {last_error}[/dim]")
            recent_requests = list(self.proxy.get("recent_requests") or [])
            for req in recent_requests[-2:]:
                method = str(req.get("method") or "?")[:6]
                path = str(req.get("path") or req.get("url") or "")[:42]
                status = req.get("status_code") or "?"
                lines.append(f"[dim]{method} {status} {path}[/dim]")

        if self.ghost_runtime:
            active = bool(self.ghost_runtime.get("active"))
            proxy_count = int(self.ghost_runtime.get("proxy_count") or 0)
            state = "active" if active else "off"
            lines.append("[bold magenta]Ghost[/bold magenta]")
            lines.append(f"{state} · proxies={proxy_count}")
            coverage = self.ghost_runtime.get("coverage")
            if isinstance(coverage, dict):
                shell_cov = str(coverage.get("shell_exec") or "")[:24]
                browser_cov = str(coverage.get("browser") or "")[:24]
                nmap_cov = str(coverage.get("nmap_scan") or "")[:24]
                lines.append(
                    f"[dim]browser {browser_cov} · shell {shell_cov} · nmap {nmap_cov}[/dim]"
                )
            warning = str(self.ghost_runtime.get("warning") or "")[:78]
            if warning:
                lines.append(f"[dim]{warning}[/dim]")

        if self.egress_contract:
            counts = self.egress_contract.get("counts") or {}
            warnings = list(self.egress_contract.get("warnings") or [])
            errors = list(self.egress_contract.get("errors") or [])
            lines.append("[bold]Egress[/bold]")
            lines.append(
                "covered={covered} partial={partial} direct={direct} delegated={delegated}".format(
                    covered=int(counts.get("low") or 0),
                    partial=int(counts.get("partial") or 0),
                    direct=int(counts.get("direct") or 0),
                    delegated=int(counts.get("delegated") or 0),
                )
            )
            for item in (errors or warnings)[:2]:
                lines.append(f"[dim]{str(item)[:76]}[/dim]")

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
        """공격 체인 진행 상황 + 활성 브랜치 도시에를 함께 표시."""
        lines: list[str] = []

        if self.focus_branch:
            lines.append("[bold cyan]Focus branch[/bold cyan]")
            focus = self.focus_branch
            lines.append(
                f"{focus.get('id', '?')} [{focus.get('role', '?')}/{focus.get('phase', '?')}] "
                f"{focus.get('status', '?')}"
            )
            objective = str(focus.get("objective") or "")[:84]
            next_step = str(focus.get("next_step") or "")[:84]
            crown = str(focus.get("crown_jewel") or "")[:72]
            blocker = str(focus.get("blocker") or "")[:72]
            if objective:
                lines.append(f"[dim]goal:[/dim] {objective}")
            if next_step:
                lines.append(f"[dim]next:[/dim] {next_step}")
            if crown:
                lines.append(f"[dim]crown:[/dim] {crown}")
            if blocker:
                lines.append(f"[dim]block:[/dim] {blocker}")

        if self.branch_items:
            if lines:
                lines.append("")
            lines.append("[bold]Active branch dossiers[/bold]")
            for branch in self.branch_items[:3]:
                lines.append(
                    f"{branch.get('id', '?')} [{branch.get('role', '?')}/{branch.get('phase', '?')}] "
                    f"{branch.get('status', '?')} a{branch.get('attempts', 0)}"
                )
                title = str(branch.get("title") or branch.get("vector_id") or "")[:78]
                if title:
                    lines.append(f"[dim]path:[/dim] {title}")
                objective = str(branch.get("objective") or "")[:78]
                next_step = str(branch.get("next_step") or "")[:78]
                if objective:
                    lines.append(f"[dim]goal:[/dim] {objective}")
                if next_step:
                    lines.append(f"[dim]next:[/dim] {next_step}")

        if self.chain_candidates:
            if lines:
                lines.append("")
            lines.append("[bold yellow]Pending chain candidates[/bold yellow]")
            for cand in self.chain_candidates[:3]:
                source = str(cand.get("source_type") or cand.get("source_id") or "?")[:20]
                target = str(cand.get("target_type") or cand.get("target_id") or "?")[:20]
                lines.append(f"{source} → {target}")
                rationale = str(cand.get("rationale") or "")[:84]
                crown = str(cand.get("crown_jewel") or "")[:72]
                if rationale:
                    lines.append(f"[dim]why:[/dim] {rationale}")
                if crown:
                    lines.append(f"[dim]crown:[/dim] {crown}")

        if self.campaign_groups:
            if lines:
                lines.append("")
            lines.append("[bold cyan]Active campaigns[/bold cyan]")
            for camp in self.campaign_groups[:3]:
                family = str(camp.get("family") or "?")
                crown = str(camp.get("crown_jewel") or "")[:52]
                roles = "/".join(str(r) for r in (camp.get("roles") or [])[:2]) or "?"
                phases = "/".join(str(p) for p in (camp.get("phases") or [])[:2]) or "?"
                lines.append(
                    f"{family} [{roles}:{phases}] "
                    f"branches={camp.get('branch_count', 0)} blockers={camp.get('blocking_count', 0)}"
                )
                headline = str(camp.get("headline") or "")[:78]
                next_step = str(camp.get("next_step") or "")[:84]
                if headline:
                    lines.append(f"[dim]from:[/dim] {headline}")
                if crown:
                    lines.append(f"[dim]crown:[/dim] {crown}")
                if next_step:
                    lines.append(f"[dim]next:[/dim] {next_step}")

        if self.focus_campaign:
            if lines:
                lines.append("")
            lines.append("[bold white]Campaign detail[/bold white]")
            family = str(self.focus_campaign.get("family") or "?")
            crown = str(self.focus_campaign.get("crown_jewel") or "")[:72]
            objective = str(self.focus_campaign.get("objective") or "")[:88]
            next_step = str(self.focus_campaign.get("next_step") or "")[:88]
            if family:
                lines.append(f"[dim]family:[/dim] {family}")
            if crown:
                lines.append(f"[dim]crown:[/dim] {crown}")
            if objective:
                lines.append(f"[dim]goal:[/dim] {objective}")
            if next_step:
                lines.append(f"[dim]next:[/dim] {next_step}")
            findings = list(self.focus_campaign.get("findings") or [])
            if findings:
                lines.append("[bold green]findings[/bold green]")
                for finding in findings[:2]:
                    lines.append(
                        f"{finding.get('severity', '?')} {finding.get('finding_type', '?')} "
                        f"{str(finding.get('title') or '')[:58]}"
                    )
            reviews = list(self.focus_campaign.get("reviews") or [])
            if reviews:
                lines.append("[bold red]reviews[/bold red]")
                for review in reviews[:2]:
                    lines.append(
                        f"{review.get('stage', '?')} {review.get('status', '?')} "
                        f"{str(review.get('title') or '')[:52]}"
                    )
            delegated = list(self.focus_campaign.get("delegated_workers") or [])
            if delegated:
                lines.append("[bold magenta]delegated workers[/bold magenta]")
                for worker in delegated[:2]:
                    lines.append(
                        f"{worker.get('id', '?')} [{worker.get('role', '?')}/{worker.get('phase', '?')}] "
                        f"{worker.get('status', '?')}"
                    )
                    escalation_status = str(worker.get("escalation_status") or "")
                    escalation_reason = str(worker.get("escalation_reason") or "")[:72]
                    next_step = str(worker.get("next_step") or "")[:72]
                    if escalation_status:
                        lines.append(f"[dim]escalation:[/dim] {escalation_status}")
                    if escalation_reason:
                        lines.append(f"[dim]why:[/dim] {escalation_reason}")
                    if next_step:
                        lines.append(f"[dim]next:[/dim] {next_step}")

        if self.blocking_branches:
            if lines:
                lines.append("")
            lines.append("[bold red]Finish blockers[/bold red]")
            for branch in self.blocking_branches[:3]:
                lines.append(
                    f"{branch.get('id', '?')} [{branch.get('role', '?')}/{branch.get('phase', '?')}] "
                    f"p{branch.get('priority', 0)} a{branch.get('attempts', 0)}"
                )
                blocker = str(branch.get("blocker") or "")[:72]
                objective = str(branch.get("objective") or "")[:78]
                next_step = str(branch.get("next_step") or "")[:78]
                if blocker:
                    lines.append(f"[dim]why:[/dim] {blocker}")
                if objective:
                    lines.append(f"[dim]goal:[/dim] {objective}")
                if next_step:
                    lines.append(f"[dim]next:[/dim] {next_step}")

        if self.memory_directives:
            if lines:
                lines.append("")
            lines.append("[bold magenta]Memory directives[/bold magenta]")
            for item in self.memory_directives[-3:]:
                lines.append(f"[dim]- {str(item)[:90]}[/dim]")

        if self.review_items:
            if lines:
                lines.append("")
            lines.append("[bold red]Open AI reviews[/bold red]")
            for item in self.review_items[:2]:
                lines.append(
                    f"{item.get('stage', '?')} {item.get('status', '?')} {str(item.get('title') or '')[:46]}"
                )
                reason = str(item.get("reason") or "")[:80]
                if reason:
                    lines.append(f"[dim]why:[/dim] {reason}")

        if self.recent_attempts:
            if lines:
                lines.append("")
            lines.append("[bold green]Recent branch activity[/bold green]")
            for attempt in self.recent_attempts[-3:]:
                status = str(attempt.get("status") or "?")[:10]
                tool = str(attempt.get("tool") or "?")[:18]
                vector = str(attempt.get("vector_id") or "?")[:18]
                summary = str(attempt.get("summary") or "")[:72]
                lines.append(f"{status:<10} {vector} via {tool}")
                if summary:
                    lines.append(f"[dim]res:[/dim] {summary}")

        if self.chains:
            if lines:
                lines.append("")
            lines.append(f"[bold blue]Linked chains[/bold blue] ({self.total_chains})")
            recent_chains = list(self.chains.items())[-2:]
            for chain_id, chain in recent_chains:
                origin = chain["origin_type"][:15]
                ep = chain["origin_endpoint"]
                max_lvl = chain["max_level"]
                level_color = {4: "bold red", 3: "red", 2: "yellow", 1: "white"}.get(max_lvl, "dim")
                lines.append(
                    f"[{level_color}]◉[/{level_color}] {chain_id} [cyan]{origin}[/cyan] [dim]{ep}[/dim] [bold]L{max_lvl}[/bold]"
                )
                crown = str(chain.get("crown_jewel") or "")[:76]
                rationale = str(chain.get("rationale") or "")[:88]
                if crown:
                    lines.append(f"  [dim]crown:[/dim] {crown}")
                if rationale:
                    lines.append(f"  [dim]why:[/dim] {rationale}")
                for i, step in enumerate(chain["steps"][:3]):
                    prefix = "└─" if i == len(chain["steps"]) - 1 else "├─"
                    lvl_c = {4: "bold red", 3: "red", 2: "yellow", 1: "white"}.get(
                        step["level"], "dim"
                    )
                    title = str(step.get("title") or step.get("reasoning") or "")[:52]
                    lines.append(
                        f"  {prefix} [{lvl_c}]L{step['level']}[/{lvl_c}] "
                        f"[cyan]{step['vector'][:14]}[/cyan] [dim]{step['endpoint']}[/dim]"
                    )
                    if title:
                        lines.append(f"      [italic dim]{title}[/italic dim]")
                if len(chain["steps"]) > 3:
                    lines.append(f"  [dim]... +{len(chain['steps']) - 3} more steps[/dim]")

        if not lines:
            lines = ["[dim]No chain operations yet — branches and links appear here[/dim]"]

        content = "\n".join(lines)
        return Panel(
            content,
            title=f"[bold]🔗 Chain Ops[/bold] [dim](linked: {self.total_chains})[/dim]",
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

        styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "informational": "dim",
        }
        labels = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Info",
        }

        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = self.findings_count.get(sev, 0)
            style = styles[sev]
            sev_table.add_row(f"[{style}]{labels[sev]}[/{style}]", f"[{style}]{count}[/{style}]")

        sev_table.add_row("", "")
        sev_table.add_row("[bold]Total[/bold]", f"[bold cyan]{self.total_findings}[/bold cyan]")

        return Panel(
            sev_table,
            title="[bold]Findings[/bold]",
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
            parts.append(
                f"[bold]Score:[/bold] [cyan]{self.score['total']:.0f}/1000[/cyan] [{self.score['grade']}]"
            )
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
            Layout(self._render_brain_thinking(), size=8, name="thinking"),
            Layout(self._render_agent_monitor(), size=15, name="agents"),
            Layout(self._render_control_plane(), size=11, name="control"),
            Layout(self._render_attack_feed(), name="attacks"),
        )
        # Right column: hits + chain dossiers + findings
        layout["right"].split(
            Layout(self._render_hits(), size=8, name="hits"),
            Layout(self._render_chains(), name="chains"),
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
