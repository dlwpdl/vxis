"""Pure aggregator: turn the live scan event stream into a navigable iteration list.

The scan loop emits typed events (``brain_thinking``, ``attack``, ``hit``,
``chain_start``/``chain_step``, ``control_plane``) through a single callback. The
TUI wants to render those as an *iteration tree* — one node per Brain thinking
round — with a drill-in timeline of the narrative lines under each node.

``ScanEventModel`` is the data behind that view: feed it the raw events via
``handle`` and it groups them into :class:`Iteration` records keyed by the
Brain's iteration number. It reuses :func:`vxis.agent.event_log.format_event`
for the human-readable timeline lines so the tree and the scan log stay in sync.

Pure: no I/O, no global state, no network. Never raises on missing keys.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vxis.agent.attack_taxonomy import attack_category
from vxis.agent.event_log import format_event

# Event types whose narrative lines attach to the current iteration's timeline
# (creating an implicit index-0 "scan" iteration if Brain has not spoken yet).
_TIMELINE_EVENTS = frozenset({"attack", "hit", "chain_start", "chain_step"})


@dataclass
class Iteration:
    """One Brain thinking round and the narrative timeline produced under it."""

    index: int
    topic: str
    status: str = "running"
    timeline: list[str] = field(default_factory=list)
    found: int = 0


class ScanEventModel:
    """Aggregate the scan event stream into a navigable list of iterations."""

    def __init__(self) -> None:
        self.iterations: list[Iteration] = []
        # Latest state per delegated agent (id → dict), harvested from the
        # control_plane snapshot — the data behind the nested parallel agent tree.
        self.agents: dict[str, dict] = {}

    @property
    def current(self) -> Iteration | None:
        """The most recent iteration, or ``None`` if none exist yet."""
        return self.iterations[-1] if self.iterations else None

    def get(self, index: int) -> Iteration | None:
        """Return the iteration at list position ``index`` (not its ``.index``)."""
        if 0 <= index < len(self.iterations):
            return self.iterations[index]
        return None

    def handle(self, event_type: str, data: dict | None) -> None:
        """Fold one live scan event into the iteration list. Never raises."""
        d = data or {}

        if event_type == "brain_thinking":
            self._handle_brain_thinking(d)
        elif event_type in _TIMELINE_EVENTS:
            current = self.current
            if current is None:
                current = self._append_iteration(index=0, topic="Scan")
            if event_type == "hit":
                current.found += 1
            self._append_line(current, event_type, d)
        elif event_type == "control_plane":
            self._handle_control_plane(d)
        # anything else (unknown): skip — no crash.

    # -- internals ----------------------------------------------------------

    def _handle_control_plane(self, d: dict) -> None:
        # Merge the latest agent states (delegated workers) by id; newest wins.
        for agent in d.get("agents") or []:
            if isinstance(agent, dict) and agent.get("id"):
                self.agents[str(agent["id"])] = agent

    def agent_tree(self) -> list[dict]:
        """Nested ``[{agent, children}]`` view of the delegated agents."""
        from vxis.agent.agent_tree import build_agent_tree

        return build_agent_tree(list(self.agents.values()))

    def _handle_brain_thinking(self, d: dict) -> None:
        new_index = d.get("iteration")
        current = self.current
        if current is None or new_index != current.index:
            topic = self._topic_from_vectors(d)
            current = self._append_iteration(index=new_index, topic=topic)
        self._append_line(current, "brain_thinking", d)

    @staticmethod
    def _topic_from_vectors(d: dict) -> str:
        # The topic is what the operator reads in the tree, so map the internal
        # vector id to its human pentest category ("SQL Injection", "SSRF", …).
        vectors = d.get("vectors") or []
        if vectors and isinstance(vectors[0], dict):
            vid = vectors[0].get("id")
            if vid:
                return attack_category(str(vid))
        return "Scan"

    def _append_iteration(self, index: int, topic: str) -> Iteration:
        it = Iteration(index=index, topic=topic)
        self.iterations.append(it)
        return it

    @staticmethod
    def _append_line(iteration: Iteration, event_type: str, d: dict) -> None:
        line = format_event(event_type, d)
        if line is not None:
            iteration.timeline.append(line)


__all__ = ["Iteration", "ScanEventModel"]
