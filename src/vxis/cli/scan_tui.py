"""Strix-style interactive scan TUI (Textual).

An alternative to the Rich-Live ``ScanLiveDisplay``: instead of a fixed dashboard,
this renders a **navigable iteration tree** the operator can drill into — ↑/↓ (or
click) to move between Brain thinking rounds, and the detail pane shows that
round's timeline (🧠 thinking / 🎯 attack / 🔎 finding / 🔗 chain) coloured by
:func:`vxis.agent.tui_renderers.render_detail`. A footer line carries the live
cost estimate (model×role) and the box/ghost/mode flags so "is ghost on?" is
always answerable.

Data flow: the scan loop's event callback calls :meth:`ScanTUI.feed_event`
(marshalled onto the UI thread with ``call_from_thread`` by the caller). Events
fold into a :class:`~vxis.agent.scan_event_model.ScanEventModel` (tree structure)
while the raw payloads are kept per-iteration for the coloured detail pane.

Headless/non-TTY runs never construct this — the CLI falls back to ``ScanLiveDisplay``.
"""
from __future__ import annotations

from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, Label, ListItem, ListView, RichLog, Static

from vxis.agent.llm_cost import summarize_usage
from vxis.agent.scan_event_model import ScanEventModel
from vxis.agent.tui_renderers import render_detail


def _iter_label(it: Any) -> str:
    """One-line ListView label for an iteration: index · topic · found badge."""
    badge = f"  [bold red]✦{it.found}[/]" if it.found else ""
    return f"[dim]iter {it.index}[/] [bold]{it.topic}[/]{badge}"


class ScanTUI(App):
    """Interactive scan view. Feed it events via :meth:`feed_event`."""

    CSS = """
    Horizontal { height: 1fr; }
    #iters { width: 38%; border-right: solid $accent; }
    #detail { width: 1fr; padding: 0 1; }
    #status { height: 1; dock: bottom; background: $panel; color: $text; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("up", "focus_iters", ""),
        ("down", "focus_iters", ""),
    ]

    def __init__(
        self,
        *,
        target: str = "",
        profile: str = "",
        brain: str = "",
        box_mode: str = "",
        ghost: bool = False,
    ) -> None:
        super().__init__()
        self.model = ScanEventModel()
        self._raw: dict[int, list[tuple[str, dict]]] = {}
        self._usage_rows: list[dict] = []
        self._rendered = 0
        self._meta = {
            "target": target,
            "profile": profile,
            "brain": brain,
            "box_mode": box_mode or "black",
            "ghost": ghost,
        }

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield ListView(id="iters")
            yield RichLog(id="detail", markup=True, wrap=True, highlight=False)
        yield Static(self._status_text(), id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "VXIS"
        self.sub_title = self._meta["target"]
        self.query_one("#iters", ListView).focus()

    # -- public feed --------------------------------------------------------

    def feed_event(self, event_type: str, data: dict | None) -> None:
        """Fold one scan event into the model + keep the raw payload for detail.

        Safe to call from the UI thread (the caller marshals worker-thread events
        via ``App.call_from_thread``). Never raises on bad input.
        """
        try:
            self.model.handle(event_type, data)
            pos = len(self.model.iterations) - 1
            if pos >= 0:
                self._raw.setdefault(pos, []).append((event_type, data or {}))
            if event_type in ("hit", "attack", "brain_thinking"):
                self._record_usage(data or {})
            self._sync()
        except Exception:  # a display must never crash the scan
            pass

    def _record_usage(self, data: dict) -> None:
        # control_plane carries telemetry; brain_thinking/attack don't carry
        # tokens. We harvest token/model/role from any event that does.
        model = data.get("model") or data.get("llm_model")
        if not model:
            return
        self._usage_rows.append({
            "model": str(model),
            "role": str(data.get("role") or "?"),
            "input_tokens": int(data.get("input_tokens") or 0),
            "output_tokens": int(data.get("output_tokens") or 0),
        })

    # -- rendering ----------------------------------------------------------

    def _sync(self) -> None:
        if not self.is_running:
            return
        iters = self.model.iterations
        lv = self.query_one("#iters", ListView)
        # Append items for any newly-created iterations.
        for i in range(self._rendered, len(iters)):
            lv.append(ListItem(Label(_iter_label(iters[i])), id=f"it{i}"))
        self._rendered = len(iters)
        # Keep the current row's label fresh (found badge) + auto-follow the tail.
        if iters:
            cur_pos = len(iters) - 1
            try:
                self.query_one(f"#it{cur_pos} Label", Label).update(_iter_label(iters[cur_pos]))
            except Exception:
                pass
            if lv.index is None:
                lv.index = cur_pos
            if lv.index == cur_pos:
                self._render_detail(cur_pos)
        self.query_one("#status", Static).update(self._status_text())

    def _render_detail(self, pos: int) -> None:
        log = self.query_one("#detail", RichLog)
        log.clear()
        for event_type, data in self._raw.get(pos, []):
            markup = render_detail(event_type, data)
            if markup:
                log.write(markup)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.index is not None:
            self._render_detail(event.list_view.index)

    def action_focus_iters(self) -> None:
        self.query_one("#iters", ListView).focus()

    # -- status bar ---------------------------------------------------------

    def _status_text(self) -> str:
        m = self._meta
        ghost = "👻 ghost ON" if m["ghost"] else "ghost off"
        summary = summarize_usage(self._usage_rows)
        cost = (
            f"💸 ~${summary['total_cost_usd']:.4f} / {summary['total_tokens']:,} tok"
            if self._usage_rows else "💸 ~$0 / 0 tok"
        )
        found = sum(it.found for it in self.model.iterations)
        return (
            f" {cost}   ⚫ box:{m['box_mode']}   {ghost}   "
            f"🔎 {found} finding(s)   [dim]q=quit ↑↓=navigate[/]"
        )


__all__ = ["ScanTUI"]
