"""Strix-style scan-log narrative — format live events into one-line entries so
`tail -f logs/scan_*.log` (and later the TUI drill-in) shows what attack ran,
how, and the result. format_event is pure; noisy/telemetry events skip (None)."""
from vxis.agent.event_log import format_event


def test_attack_event_shows_vector_method_endpoint():
    line = format_event("attack", {
        "vector_id": "skill:test_injection",
        "method": "SKILL",
        "endpoint": "/rest/user/login",
    })
    assert line is not None
    assert "skill:test_injection" in line
    assert "SKILL" in line
    assert "/rest/user/login" in line


def test_brain_thinking_shows_reasoning():
    line = format_event("brain_thinking", {
        "iteration": 3, "max_iters": 120,
        "vectors": [{"id": "web:auth-bypass", "reasoning": "iter 3/120 - SQLi on /login"}],
    })
    assert line is not None
    assert "SQLi on /login" in line


def test_hit_event_shows_finding_and_severity():
    line = format_event("hit", {
        "finding_id": "F-1", "vector_id": "sqli", "confidence": "critical", "level": 4,
    })
    assert line is not None
    assert "sqli" in line
    assert "critical" in line


def test_chain_events_show_chain():
    s = format_event("chain_start", {"chain_id": "C1", "vector_id": "idor", "endpoint": "/api/u/1"})
    assert s is not None and "C1" in s and "idor" in s


def test_noisy_and_unknown_events_skip():
    assert format_event("control_plane", {"note": "telemetry"}) is None
    assert format_event("something_unknown", {}) is None


def test_brain_thinking_without_reasoning_skips():
    assert format_event("brain_thinking", {"vectors": []}) is None
