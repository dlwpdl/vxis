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


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


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
    # Escape the bracket so Rich renders a literal "[running]" instead of parsing
    # "[running]" as a (bogus) markup tag and swallowing the status text entirely.
    tail = f"  [dim]\\[{status}][/dim]" if status else ""
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
        # Stable key -> TreeNode map so _sync() can reconcile in place instead of
        # clear()+rebuild (which wiped cursor/selection/expansion on every event).
        # Keys: "director", "agents", ("iter", pos), ("agent", id).
        self._tnodes: dict[Any, Any] = {}
        self._tlabels: dict[Any, str] = {}          # last label per key (diff guard)
        self._tagent_parent: dict[str, Any] = {}    # agent id -> parent key (reparent detect)
        self._tagent_branch: dict[str, bool] = {}   # agent id -> created as expandable branch
        # Detail pane "follow" mode: stream the narrative live (Strix-style) until
        # the operator drills into a specific node; drilling freezes on that node.
        self._follow = True
        self._narrative_started = False
        self.scan_runner = scan_runner
        self.scan_error: BaseException | None = None
        self._done = False
        self._evt_count = 0
        self._meta = {
            "target": target, "profile": profile, "brain": brain,
            "box_mode": box_mode or "black", "ghost": ghost,
            "injection_mode": "pending",
            "context": "ctx n/a",
            "brain_decisions": 0,
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
            self._capture_runtime_state(event_type, data or {})
            self.model.handle(event_type, data)
            if event_type in ("brain_thinking", "attack", "hit", "chain_start", "chain_step"):
                pos = len(self.model.iterations) - 1
                if pos >= 0:
                    self._raw.setdefault(pos, []).append((event_type, data or {}))
            self._sync()
            # Live follow: stream the narrative into the detail pane as it happens
            # (no click needed) — unless the operator has drilled into a node.
            if self._follow:
                markup = render_detail(event_type, data or {})
                if markup:
                    log = self.query_one("#detail", RichLog)
                    if not self._narrative_started:
                        log.clear()  # drop the "scan starting…" placeholder
                        self._narrative_started = True
                    log.write(markup)
        except Exception as exc:
            self._dbg(f"feed_event _sync FAILED for {event_type}: {exc!r}")

    def _capture_runtime_state(self, event_type: str, data: dict) -> None:
        if event_type == "injection_approval_result":
            decision = str(data.get("decision") or "").strip().lower()
            if decision:
                self._meta["injection_mode"] = decision
            return
        if event_type != "control_plane":
            return
        telemetry = data.get("telemetry") or {}
        if not isinstance(telemetry, dict):
            return
        self._meta["brain_decisions"] = _as_int(telemetry.get("brain_decisions"))
        compression = telemetry.get("memory_compression") or {}
        if isinstance(compression, dict):
            before = _as_int(compression.get("last_tokens_before"))
            threshold = _as_int(compression.get("last_threshold"))
            saved = _as_int(compression.get("total_tokens_saved"))
            if threshold > 0:
                self._meta["context"] = f"ctx {before:,}/{threshold:,}"
                if saved > 0:
                    self._meta["context"] += f" saved {saved:,}"

    def _sync(self) -> None:
        """Reconcile the model into the tree IN PLACE — never clear()+rebuild.

        Rebuilding the whole tree on every event (the old behaviour) recreated all
        TreeNodes, so the cursor, selection and expansion state were wiped on each
        scan event and the tree was impossible to click/navigate while a scan ran.
        Instead we keep a stable ``key -> TreeNode`` map and only add new nodes,
        relabel changed ones, and remove vanished ones.
        """
        if not self.is_running:
            return
        self._reconcile_director()
        self._reconcile_agents()
        self.query_one("#status", Static).update(self._status_text())

    def _set_label(self, key: Any, node: Any, label: str) -> None:
        """set_label only when the text actually changed (avoid needless redraws)."""
        if self._tlabels.get(key) != label:
            node.set_label(label)
            self._tlabels[key] = label

    def _reconcile_director(self) -> None:
        tree = self.query_one("#tree", Tree)
        iters = self.model.iterations
        cur_topic = iters[-1].topic if iters else "starting…"
        state = "done" if self._done else "running"
        dlabel = f"[bold]Director[/bold] — {cur_topic} [dim][{state}][/dim]"

        director = self._tnodes.get("director")
        if director is None:
            # Created once, before the Agents branch, so the Director is always the
            # first child of the root (the structure the pilot tests rely on).
            director = tree.root.add(dlabel, data={"kind": "root"}, expand=True)
            self._tnodes["director"] = director
            self._tlabels["director"] = dlabel
        else:
            self._set_label("director", director, dlabel)

        # Iterations are append-only and list-position keyed; only add new leaves
        # and relabel ones whose finding count / topic changed in place.
        for i, it in enumerate(iters):
            key = ("iter", i)
            node = self._tnodes.get(key)
            label = _iter_label(it)
            if node is None:
                node = director.add_leaf(label, data={"kind": "iter", "pos": i})
                self._tnodes[key] = node
                self._tlabels[key] = label
            else:
                self._set_label(key, node, label)

    def _reconcile_agents(self) -> None:
        agent_tree = self.model.agent_tree()
        if not agent_tree:
            return
        tree = self.query_one("#tree", Tree)
        agents_node = self._tnodes.get("agents")
        if agents_node is None:
            agents_node = tree.root.add("", data={"kind": "agents"}, expand=True)
            self._tnodes["agents"] = agents_node
        self._set_label("agents", agents_node, f"[bold]Agents[/bold] [dim]({len(self.model.agents)})[/dim]")

        self._walk_agents(agents_node, "agents", agent_tree)
        self._prune_agents()

    def _walk_agents(self, parent_node: Any, parent_key: Any, nodes: list[dict]) -> None:
        for node in nodes:
            agent = node["agent"]
            aid = str(agent.get("id") or "?")
            key = ("agent", aid)
            children = node.get("children") or []
            existing = self._tnodes.get(key)

            # Recreate a node only if it moved under a new parent, or it was made a
            # leaf but now needs to host children (Textual leaves can't grow them).
            # Both are rare — the director appears before its workers.
            if existing is not None:
                reparented = self._tagent_parent.get(aid) != parent_key
                upgraded = bool(children) and not self._tagent_branch.get(aid, False)
                if reparented or upgraded:
                    self._remove_agent(key)
                    existing = None

            label = _agent_label(agent)
            if existing is None:
                if children:
                    tn = parent_node.add(label, data={"kind": "agent", "agent": agent}, expand=True)
                else:
                    tn = parent_node.add_leaf(label, data={"kind": "agent", "agent": agent})
                self._tnodes[key] = tn
                self._tlabels[key] = label
                self._tagent_parent[aid] = parent_key
                self._tagent_branch[aid] = bool(children)
            else:
                tn = existing
                # Refresh node.data every time: on_tree_node_highlighted/selected
                # reads it live to render the detail pane (status/task), so it must
                # carry the latest agent dict, not just the latest label.
                tn.data = {"kind": "agent", "agent": agent}
                self._set_label(key, tn, label)

            self._walk_agents(tn, key, children)

    def _prune_agents(self) -> None:
        """Drop nodes for agents the model no longer reports (rare; e.g. merged)."""
        live = set(self.model.agents)
        stale = [k for k in self._tnodes
                 if isinstance(k, tuple) and k[0] == "agent" and k[1] not in live]
        for key in stale:
            self._remove_agent(key)

    def _remove_agent(self, key: Any) -> None:
        """Remove an agent node + its subtree from the widget and forget tracking."""
        node = self._tnodes.get(key)
        if node is not None:
            try:
                node.remove()  # removes the whole TreeNode subtree from the widget
            except Exception:
                pass
        self._forget_agent_subtree(key)

    def _forget_agent_subtree(self, key: Any) -> None:
        # Removing a node drops its descendants' widgets too, so forget their
        # tracking as well — they get recreated cleanly if they reappear.
        for child_aid in [a for a, p in list(self._tagent_parent.items()) if p == key]:
            self._forget_agent_subtree(("agent", child_aid))
        self._tnodes.pop(key, None)
        self._tlabels.pop(key, None)
        self._tagent_parent.pop(key[1], None)
        self._tagent_branch.pop(key[1], None)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        self._on_node_focus(event.node.data)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        self._on_node_focus(event.node.data)

    def _on_node_focus(self, data: Any) -> None:
        """A tree node gained focus (click or ↑↓). Drilling into a specific
        iteration/agent freezes the pane on that node's logs; focusing the
        Director / a group / the tree root resumes the live full-narrative follow."""
        if isinstance(data, dict) and data.get("kind") in ("iter", "agent"):
            self._follow = False
            self._render_detail(data)
        else:
            self._follow = True
            self._render_detail({"kind": "root"})

    def _markup_for(self, data: Any) -> list[str]:
        """Rich-markup lines to show for a focused node (pure, never raises).

        - ``iter``  → just that iteration's narrative
        - ``root``  → the whole narrative across every iteration (Director view)
        - ``agent`` → the agent's id/role/status/task summary (per-agent log
          streams need the engine to attribute events to sub-agents; until then
          the full stream lives under the Director view)
        """
        if not isinstance(data, dict):
            return []
        kind = data.get("kind")
        if kind == "iter":
            return [m for et, pl in self._raw.get(data.get("pos", -1), []) if (m := render_detail(et, pl))]
        if kind == "root":
            out: list[str] = []
            for pos in sorted(self._raw):
                for et, pl in self._raw[pos]:
                    m = render_detail(et, pl)
                    if m:
                        out.append(m)
            return out
        if kind == "agent":
            agent = data.get("agent") or {}
            lines = [
                f"[bold cyan]{agent.get('id', '?')}[/bold cyan]  "
                f"[dim]{agent.get('role', '')} · {agent.get('status', '')}[/dim]"
            ]
            task = str(agent.get("task") or agent.get("instruction") or "").strip()
            if task:
                lines.append(f"[white]{task}[/white]")
            return lines
        return []

    def _render_detail(self, data: Any) -> None:
        log = self.query_one("#detail", RichLog)
        log.clear()
        self._narrative_started = True
        for line in self._markup_for(data):
            log.write(line)

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
            f"{sep}inject {m['injection_mode']}"
            f"{sep}ghost {'on' if m['ghost'] else 'off'}"
            f"{sep}{m['context']}{sep}brain {m['brain_decisions']}"
            f"{sep}{found} findings"
            f"{sep}[dim]q quit · ↑↓ move · e expand[/dim]"
        )


__all__ = ["ScanTUI"]
