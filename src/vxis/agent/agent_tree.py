"""Build a nested agent graph from the flat agent list the scan emits.

The scan's ``control_plane`` event carries ``agents`` — a flat list of agent
dicts, each with ``id``, ``parent_id``, ``status`` (running/waiting/done/…),
``role`` and ``task``. The interactive TUI wants to show these as a *tree*: the
root director with its delegated sub-agents nested underneath, so the operator
sees what is running in parallel at a glance (Strix-style).

``build_agent_tree`` turns the flat list into nested ``{"agent", "children"}``
nodes. Pure, order-stable, cycle-safe (a self/loop parent is treated as a root).
"""
from __future__ import annotations

from typing import Any


def build_agent_tree(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flat agents → nested ``[{"agent": <dict>, "children": [...]}]`` (roots first).

    Roots are agents with no ``parent_id`` (or a ``parent_id`` not present in the
    list). Insertion order is preserved among siblings.
    """
    by_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for a in agents or []:
        aid = str(a.get("id") or "").strip()
        if not aid or aid in by_id:
            continue
        by_id[aid] = a
        order.append(aid)

    children: dict[str, list[str]] = {aid: [] for aid in order}
    roots: list[str] = []
    for aid in order:
        pid = str(by_id[aid].get("parent_id") or "").strip()
        if pid and pid in by_id and pid != aid:
            children[pid].append(aid)
        else:
            roots.append(aid)

    def _node(aid: str, seen: frozenset[str]) -> dict[str, Any]:
        if aid in seen:  # cycle guard — stop descending
            return {"agent": by_id[aid], "children": []}
        seen = seen | {aid}
        return {
            "agent": by_id[aid],
            "children": [_node(c, seen) for c in children[aid]],
        }

    return [_node(r, frozenset()) for r in roots]


__all__ = ["build_agent_tree"]
