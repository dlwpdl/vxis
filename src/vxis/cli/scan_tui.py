"""Strix-style interactive scan TUI (Textual).

A navigable **tree** the operator drills into (↑/↓ or click), not a fixed
dashboard:

    Scan: <target>
    ├─ Director — <current category> [running]      ← the main brain's steps
    │   ├─ 1  Recon
    │   ├─ 2  SQL Injection · 2 found
    │   └─ 3  SSRF
    └─ Agents (2)                                    ← delegated sub-agents,
        └─ director                                    nested by parent_id, with
            ├─ ● w1  SQL Injection [running]           live parallel status
            └─ ◌ w2  SSRF [waiting]

Selecting a node fills the detail pane: an iteration shows its colour-coded
timeline (via :func:`~vxis.agent.tui_renderers.render_detail`); an agent shows
its task/role/status. A footer carries the live cost + box/ghost/finding flags.

Data flow: the scan loop's event callback → :meth:`feed_event` (marshalled onto
the UI thread). brain_thinking/attack/hit/chain fold into a
:class:`~vxis.agent.scan_event_model.ScanEventModel` (iterations); control_plane
carries the delegated-agent snapshot (nested via parent_id). Headless/non-TTY
never construct this — the CLI falls back to ``ScanLiveDisplay``.
"""
from __future__ import annotations

from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, RichLog, Static, Tree

from vxis.agent.attack_taxonomy import attack_category
from vxis.agent.llm_cost import summarize_usage
from vxis.agent.scan_event_model import ScanEventModel
from vxis.agent.tui_renderers import render_detail

_AGENT_ICON = {"running": "●", "waiting": "◌", "done": "✓", "blocked": "■"}


def _iter_label(it: Any) -> str:
    found = f"  [dim]· {it.found} found[/dim]" if it.found else ""
    tint = "green" if it.found else "white"
    return f"[dim]{it.index:>2}[/dim]  [{tint}]{it.topic}[/{tint}]{found}"


def _agent_label(agent: dict) -> str:
    status = str(agent.get("status") or "").lower()
    icon = _AGENT_ICON.get(status, "·")
    aid = str(agent.get("id") or "?")
    category = attack_category(str(agent.get("task") or agent.get("skill") or agent.get("role") or ""))
    color = {"running": "bold cyan", "waiting": "yellow", "done": "green", "blocked": "red"}.get(status, "white")
    tail = f"  [dim][{status}][/dim]" if status else ""
    return f"[{color}]{icon} {aid}[/{color}]  {category}{tail}"


class ScanTUI(App):
    """Interactive scan view. Feed it events via :meth:`feed_event`."""

    CSS = """
    Horizontal { height: 1fr; }
    #tree { width: 42%; border-right: solid $accent; }
    #detail { width: 1fr; padding: 0 1; }
    #status { height: 1; dock: bottom; background: $panel; color: $text; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("e", "expand_all", "Expand"),
    ]

    def __init__(
        self,
        *,
        target: str = "",
        profile: str = "",
        brain: str = "",
        box_mode: str = "",
        ghost: bool = False,
        scan_runner: Any = None,
    ) -> None:
        super().__init__()
        self.model = ScanEventModel()
        self._raw: dict[int, list[tuple[str, dict]]] = {}
        self.scan_runner = scan_runner
        self.scan_error: BaseException | None = None
        self._done = False
        self._evt_count = 0
        self._meta = {
            "target": target, "profile": profile, "brain": brain,
            "box_mode": box_mode or "black", "ghost": ghost,
        }

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            tree: Tree = Tree(f"Scan: {self._meta['target']}", id="tree")
            tree.root.expand()
            yield tree
            yield RichLog(id="detail", markup=True, wrap=True, highlight=False)
        yield Static(self._status_text(), id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "VXIS"
        self.sub_title = self._meta["target"]
        self.query_one("#tree", Tree).focus()
        self.query_one("#detail", RichLog).write(
            "[dim]Scan starting — the Brain's first decision can take ~10-30s on a "
            "large-context model. Steps appear on the left; select one to inspect.[/dim]"
        )
        if self.scan_runner is not None:
            self.run_worker(self._drive_scan, thread=True, exclusive=True, name="scan")

    # -- scan driving (worker thread) ---------------------------------------

    def _dbg(self, msg: str) -> None:
        """Opt-in diagnostic (VXIS_TUI_DEBUG=1) — direct file append, immune to
        Textual stdout capture / logging config, so we can see the live path."""
        import os

        if not os.environ.get("VXIS_TUI_DEBUG"):
            return
        try:
            with open("/tmp/vxis_tui_debug.log", "a", encoding="utf-8") as fh:
                fh.write(msg + "\n")
        except Exception:
            pass

    def thread_safe_feed(self, event_type: str, data: dict | None) -> None:
        try:
            self.call_from_thread(self.feed_event, event_type, data)
        except Exception as exc:
            self._dbg(f"call_from_thread FAILED for {event_type}: {exc!r}")

    def _drive_scan(self) -> None:
        import asyncio

        self._dbg("worker started")
        try:
            asyncio.run(self.scan_runner())
            self._dbg(f"scan returned: iterations={len(self.model.iterations)} "
                      f"agents={len(self.model.agents)} events={self._evt_count}")
        except BaseException as exc:
            self.scan_error = exc
            self._dbg(f"scan ERROR: {exc!r}")
        finally:
            try:
                self.call_from_thread(self._on_scan_done)
            except Exception:
                self._done = True

    def _on_scan_done(self) -> None:
        self._done = True
        try:
            self._sync()
            self.query_one("#detail", RichLog).write(
                "[bold green]── scan complete ──[/bold green] [dim]press q to exit · ↑↓ to browse[/dim]"
            )
        except Exception:
            pass

    # -- feed + render ------------------------------------------------------

    def feed_event(self, event_type: str, data: dict | None) -> None:
        """Fold one scan event into the model + raw store, then refresh the tree.
        Never raises — a display bug must not kill the scan."""
        self._evt_count += 1
        if self._evt_count <= 20:
            self._dbg(f"event #{self._evt_count} {event_type}")
        try:
            self.model.handle(event_type, data)
            if event_type in ("brain_thinking", "attack", "hit", "chain_start", "chain_step"):
                pos = len(self.model.iterations) - 1
                if pos >= 0:
                    self._raw.setdefault(pos, []).append((event_type, data or {}))
            self._sync()
        except Exception as exc:
            self._dbg(f"feed_event _sync FAILED for {event_type}: {exc!r}")

    def _sync(self) -> None:
        if not self.is_running:
            return
        tree = self.query_one("#tree", Tree)
        tree.clear()
        iters = self.model.iterations
        cur_topic = iters[-1].topic if iters else "starting…"
        state = "done" if self._done else "running"

        director = tree.root.add(f"[bold]Director[/bold] — {cur_topic} [dim][{state}][/dim]",
                                 data={"kind": "root"}, expand=True)
        for i, it in enumerate(iters):
            director.add_leaf(_iter_label(it), data={"kind": "iter", "pos": i})

        agent_tree = self.model.agent_tree()
        if agent_tree:
            total = len(self.model.agents)
            agents_node = tree.root.add(f"[bold]Agents[/bold] [dim]({total})[/dim]",
                                        data={"kind": "agents"}, expand=True)
            for node in agent_tree:
                self._add_agent(agents_node, node)

        self.query_one("#status", Static).update(self._status_text())

    def _add_agent(self, parent, node: dict) -> None:
        agent = node["agent"]
        children = node.get("children") or []
        label = _agent_label(agent)
        if children:
            tn = parent.add(label, data={"kind": "agent", "agent": agent}, expand=True)
            for child in children:
                self._add_agent(tn, child)
        else:
            parent.add_leaf(label, data={"kind": "agent", "agent": agent})

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        self._render_detail(event.node.data)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        self._render_detail(event.node.data)

    def _render_detail(self, data: Any) -> None:
        if not isinstance(data, dict):
            return
        log = self.query_one("#detail", RichLog)
        kind = data.get("kind")
        if kind == "iter":
            log.clear()
            for event_type, payload in self._raw.get(data.get("pos", -1), []):
                markup = render_detail(event_type, payload)
                if markup:
                    log.write(markup)
        elif kind == "agent":
            agent = data.get("agent") or {}
            log.clear()
            log.write(f"[bold cyan]{agent.get('id', '?')}[/bold cyan]  "
                      f"[dim]{agent.get('role', '')} · {agent.get('status', '')}[/dim]")
            task = str(agent.get("task") or agent.get("instruction") or "").strip()
            if task:
                log.write(f"[white]{task}[/white]")

    def action_expand_all(self) -> None:
        try:
            self.query_one("#tree", Tree).root.expand_all()
        except Exception:
            pass

    # -- status bar ---------------------------------------------------------

    def _status_text(self) -> str:
        m = self._meta
        rows: list[dict] = []
        try:
            from vxis.agent.brain_metrics import get_llm_usage_stats

            rows = get_llm_usage_stats().get("rows") or []
        except Exception:
            rows = []
        summary = summarize_usage(rows)
        cost = (
            f"~${summary['total_cost_usd']:.4f} · {summary['total_tokens']:,} tok"
            if rows else "~$0 · 0 tok"
        )
        found = sum(it.found for it in self.model.iterations)
        state = "[green]done[/green]" if self._done else "[yellow]running[/yellow]"
        sep = "  [dim]│[/dim]  "
        return (
            f" {state}{sep}{cost}{sep}box {m['box_mode']}"
            f"{sep}ghost {'on' if m['ghost'] else 'off'}{sep}{found} findings"
            f"{sep}[dim]q quit · ↑↓ move · e expand[/dim]"
        )


__all__ = ["ScanTUI"]
