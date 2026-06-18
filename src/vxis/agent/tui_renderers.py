"""Per-event-type detail renderers for the TUI drill-in detail pane.

The live scan emits typed events through one callback (``brain_thinking``,
``attack``, ``hit``, ``chain_start``/``chain_step``, ``control_plane``). When a
user drills into a single event in the TUI, ``render_detail`` turns it into a
one-line **Rich console markup** string for the detail pane — sibling to
``event_log.format_event`` (which produces plain log lines), but here we keep the
Rich tags so the pane can colourise fields.

Registry pattern: ``_RENDERERS`` maps each event type to a pure ``data -> str``
renderer, so adding a new type is one dict entry. Unknown types and telemetry
(``control_plane``) have no detail and yield ``""``.

Every returned string is valid Rich markup (balanced tags) so the caller can
hand it straight to ``rich.text.Text.from_markup`` without escaping concerns for
the literal tags we emit.

Pure: no I/O, no global mutable state.
"""
from __future__ import annotations

from typing import Callable

# Each renderer receives the (already-normalised) event payload dict and returns
# Rich markup, or "" when the event carries no displayable detail.
Renderer = Callable[[dict[str, object]], str]


def _render_brain_thinking(data: dict[str, object]) -> str:
    vectors = data.get("vectors") or []
    reasoning = ""
    if isinstance(vectors, list) and vectors and isinstance(vectors[0], dict):
        reasoning = str(vectors[0].get("reasoning") or "").strip()
    if not reasoning:
        return ""
    return f"[bold yellow]🧠 thinking[/] {reasoning}"


def _render_attack(data: dict[str, object]) -> str:
    vector_id = str(data.get("vector_id") or "?")
    method = str(data.get("method") or "")
    endpoint = str(data.get("endpoint") or "")
    return f"[bold cyan]🎯 {vector_id}[/]  [magenta]{method}[/] {endpoint}".rstrip()


def _render_hit(data: dict[str, object]) -> str:
    vector_id = str(data.get("vector_id") or data.get("finding_id") or "finding")
    confidence = str(data.get("confidence") or "")
    return f"[bold red]🔎 FINDING[/] {vector_id} [dim](severity={confidence})[/]"


def _render_chain_start(data: dict[str, object]) -> str:
    chain_id = str(data.get("chain_id") or "?")
    vector_id = str(data.get("vector_id") or "?")
    endpoint = str(data.get("endpoint") or "")
    return f"[bold green]🔗 chain {chain_id} START[/] {vector_id} @ {endpoint}".rstrip()


def _render_chain_step(data: dict[str, object]) -> str:
    chain_id = str(data.get("chain_id") or "?")
    vector_id = str(data.get("vector_id") or "?")
    endpoint = str(data.get("endpoint") or "")
    return f"[green]🔗 chain {chain_id} step[/] {vector_id} @ {endpoint}".rstrip()


# event_type -> renderer. Add a new event type by adding one entry here.
_RENDERERS: dict[str, Renderer] = {
    "brain_thinking": _render_brain_thinking,
    "attack": _render_attack,
    "hit": _render_hit,
    "chain_start": _render_chain_start,
    "chain_step": _render_chain_step,
}


def render_detail(event_type: str, data: dict[str, object] | None) -> str:
    """Render one live scan event as Rich markup for the TUI detail pane.

    Returns ``""`` for telemetry (``control_plane``), unknown event types, and
    known events that carry no displayable detail (e.g. ``brain_thinking`` with
    empty reasoning).
    """
    renderer = _RENDERERS.get(event_type)
    if renderer is None:
        return ""
    return renderer(data or {})


__all__ = ["render_detail"]
