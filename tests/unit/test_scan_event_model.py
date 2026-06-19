"""Tests for the pure scan-event aggregator (TUI iteration-tree data model).

Uses the REAL ``format_event`` (no mocks) so the asserted timeline lines match
exactly what the live scan log / TUI drill-in render.
"""
from __future__ import annotations

from vxis.agent.event_log import format_event
from vxis.agent.scan_event_model import Iteration, ScanEventModel


def test_brain_thinking_attack_hit_builds_one_iteration() -> None:
    m = ScanEventModel()
    m.handle(
        "brain_thinking",
        {"iteration": 1, "max_iters": 10, "vectors": [{"id": "web:recon", "reasoning": "probe"}]},
    )
    m.handle("attack", {"vector_id": "web:recon", "method": "GET", "endpoint": "/login"})
    m.handle("hit", {"finding_id": "F1", "vector_id": "web:recon", "level": 1, "confidence": "high"})

    assert len(m.iterations) == 1
    it = m.iterations[0]
    assert isinstance(it, Iteration)
    assert it.index == 1
    assert it.topic == "Recon"  # human category, not the raw "web:recon"
    assert it.found == 1
    # the real format_event lines must be present
    attack_line = format_event("attack", {"vector_id": "web:recon", "method": "GET", "endpoint": "/login"})
    hit_line = format_event("hit", {"finding_id": "F1", "vector_id": "web:recon", "confidence": "high"})
    assert attack_line in it.timeline
    assert hit_line in it.timeline
    assert any(line.startswith("try") for line in it.timeline)
    assert any(line.startswith("FOUND") for line in it.timeline)


def test_second_brain_thinking_starts_new_iteration() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
    m.handle("brain_thinking", {"iteration": 2, "vectors": [{"id": "web:xss", "reasoning": "b"}]})

    assert len(m.iterations) == 2
    assert m.iterations[0].index == 1
    assert m.iterations[0].topic == "Recon"
    assert m.iterations[1].index == 2
    assert m.iterations[1].topic == "XSS"
    assert m.current is m.iterations[1]


def test_same_iteration_number_does_not_create_new_iteration() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "again"}]})
    assert len(m.iterations) == 1
    assert m.iterations[0].index == 1


def test_brain_thinking_without_vectors_uses_generic_topic() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 5})
    assert len(m.iterations) == 1
    assert m.iterations[0].index == 5
    assert m.iterations[0].topic == "Scan"


def test_events_before_any_brain_thinking_land_in_index_zero_scan_iteration() -> None:
    m = ScanEventModel()
    m.handle("attack", {"vector_id": "web:recon", "method": "GET", "endpoint": "/login"})
    m.handle("hit", {"finding_id": "F1", "vector_id": "web:recon", "confidence": "low"})

    assert len(m.iterations) == 1
    it = m.iterations[0]
    assert it.index == 0
    assert it.topic == "Scan"
    assert it.found == 1
    assert any(line.startswith("try") for line in it.timeline)
    assert any(line.startswith("FOUND") for line in it.timeline)


def test_chain_events_append_to_current_timeline() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
    m.handle("chain_start", {"chain_id": "C1", "vector_id": "web:recon", "endpoint": "/a"})
    m.handle("chain_step", {"chain_id": "C1", "vector_id": "web:xss", "endpoint": "/b"})

    timeline = m.current.timeline if m.current else []
    assert format_event("chain_start", {"chain_id": "C1", "vector_id": "web:recon", "endpoint": "/a"}) in timeline
    assert format_event("chain_step", {"chain_id": "C1", "vector_id": "web:xss", "endpoint": "/b"}) in timeline


def test_unknown_and_control_plane_events_add_no_lines() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
    before = list(m.current.timeline) if m.current else []
    m.handle("control_plane", {"cpu": 0.9})
    m.handle("totally_unknown", {"foo": "bar"})
    after = list(m.current.timeline) if m.current else []
    assert before == after


def test_brain_thinking_without_reasoning_skips_line_but_creates_iteration() -> None:
    # format_event returns None for brain_thinking with no reasoning -> no timeline line,
    # but the iteration itself is still created.
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon"}]})
    assert len(m.iterations) == 1
    assert m.current is not None
    assert m.current.index == 1
    assert m.current.topic == "Recon"
    assert m.current.timeline == []


def test_handle_never_raises_on_missing_keys_or_none_data() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", None)  # no data at all
    m.handle("attack", None)
    m.handle("hit", {})
    m.handle("chain_start", None)
    # should not raise; brain_thinking(None) -> current().index is None-ish -> new iter
    assert m.current is not None


def test_get_returns_iteration_by_index_position_or_none() -> None:
    m = ScanEventModel()
    m.handle("brain_thinking", {"iteration": 1, "vectors": [{"id": "a", "reasoning": "x"}]})
    m.handle("brain_thinking", {"iteration": 2, "vectors": [{"id": "b", "reasoning": "y"}]})
    assert m.get(0) is m.iterations[0]
    assert m.get(1) is m.iterations[1]
    assert m.get(99) is None
    assert m.get(-1) is None


def test_iteration_defaults() -> None:
    it = Iteration(index=3, topic="t")
    assert it.status == "running"
    assert it.timeline == []
    assert it.found == 0
    it2 = Iteration(index=4, topic="t2")
    it.timeline.append("x")
    # default_factory: each instance has its own list
    assert it2.timeline == []


def test_current_is_none_on_empty_model() -> None:
    m = ScanEventModel()
    assert m.current is None
    assert m.get(0) is None


def test_control_plane_agents_build_nested_tree() -> None:
    m = ScanEventModel()
    m.handle("control_plane", {"agents": [
        {"id": "director", "status": "running", "role": "director"},
        {"id": "w1", "parent_id": "director", "status": "running", "task": "sqli"},
        {"id": "w2", "parent_id": "director", "status": "waiting", "task": "ssrf"},
    ]})
    assert set(m.agents) == {"director", "w1", "w2"}
    tree = m.agent_tree()
    assert [n["agent"]["id"] for n in tree] == ["director"]
    assert {c["agent"]["id"] for c in tree[0]["children"]} == {"w1", "w2"}
    # a later snapshot updates status in place (newest wins), no duplicate node
    m.handle("control_plane", {"agents": [{"id": "w1", "parent_id": "director", "status": "done"}]})
    assert m.agents["w1"]["status"] == "done"
    assert len(m.agents) == 3
