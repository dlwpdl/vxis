"""TDD specs for the TUI drill-in detail renderers.

``tui_renderers.render_detail`` turns one live scan event into Rich console
markup for the TUI's detail pane. These tests pin the contract: each known
event type yields markup that carries its key fields and at least one Rich tag,
unknown/telemetry events yield ``""``, and every produced string is valid Rich
markup (``Text.from_markup`` must not raise on it).
"""
from __future__ import annotations

import pytest
from rich.text import Text

from vxis.agent.tui_renderers import _RENDERERS, render_detail


def _assert_valid_markup(markup: str) -> None:
    """Rich must be able to parse the markup (no unclosed/invalid tags)."""
    Text.from_markup(markup)  # raises rich.errors.MarkupError on bad markup


def test_brain_thinking_includes_reasoning_and_tag() -> None:
    out = render_detail(
        "brain_thinking",
        {"vectors": [{"id": "v1", "reasoning": "login form looks injectable"}]},
    )
    assert "login form looks injectable" in out
    assert "[grey50]" in out
    _assert_valid_markup(out)


def test_brain_thinking_no_reasoning_returns_empty() -> None:
    assert render_detail("brain_thinking", {"vectors": [{"id": "v1"}]}) == ""
    assert render_detail("brain_thinking", {"vectors": []}) == ""
    assert render_detail("brain_thinking", {}) == ""


def test_brain_thinking_blank_reasoning_returns_empty() -> None:
    out = render_detail(
        "brain_thinking", {"vectors": [{"id": "v1", "reasoning": "   "}]}
    )
    assert out == ""


def test_attack_includes_vector_method_endpoint() -> None:
    out = render_detail(
        "attack",
        {"vector_id": "SQLI-01", "method": "POST", "endpoint": "/login"},
    )
    assert "SQL Injection" in out  # category, not the raw "SQLI-01"
    assert "POST" in out
    assert "/login" in out
    assert "[bold cyan]" in out
    _assert_valid_markup(out)


def test_hit_includes_category_and_severity() -> None:
    out = render_detail(
        "hit",
        {"finding_id": "F-1", "vector_id": "SQLI-01", "level": 3, "confidence": "high"},
    )
    assert "SQL Injection" in out
    assert "high" in out
    assert "found" in out
    assert "[bold green]" in out
    _assert_valid_markup(out)


def test_chain_start_includes_category_endpoint() -> None:
    out = render_detail(
        "chain_start",
        {"chain_id": "C-7", "vector_id": "IDOR-2", "endpoint": "/api/user/3"},
    )
    assert "IDOR" in out  # category
    assert "/api/user/3" in out
    assert "chain" in out
    assert "[bold magenta]" in out
    _assert_valid_markup(out)


def test_chain_step_includes_category_endpoint() -> None:
    out = render_detail(
        "chain_step",
        {"chain_id": "C-7", "vector_id": "IDOR-3", "endpoint": "/api/user/4"},
    )
    assert "IDOR" in out
    assert "/api/user/4" in out
    assert "step" in out
    assert "[magenta]" in out
    _assert_valid_markup(out)


def test_error_is_red_and_carries_message() -> None:
    out = render_detail("error", {"stage": "scan_loop", "error": "boom failed"})
    assert "boom failed" in out
    assert "red" in out          # errors stand out, not lost in the gray stream
    assert "scan_loop" in out
    _assert_valid_markup(out)


def test_error_without_message_returns_empty() -> None:
    assert render_detail("error", {"stage": "scan_loop"}) == ""


def test_control_plane_returns_empty() -> None:
    assert render_detail("control_plane", {"cpu": 0.4, "mem": 1024}) == ""


def test_unknown_event_returns_empty() -> None:
    assert render_detail("totally_made_up", {"x": 1}) == ""


def test_none_data_does_not_raise() -> None:
    # All known types must tolerate ``data=None`` without raising.
    for event_type in _RENDERERS:
        out = render_detail(event_type, None)
        assert isinstance(out, str)
        _assert_valid_markup(out)


def test_registry_maps_all_known_types() -> None:
    expected = {"brain_thinking", "attack", "hit", "chain_start", "chain_step"}
    assert expected <= set(_RENDERERS)
    for fn in _RENDERERS.values():
        assert callable(fn)


@pytest.mark.parametrize(
    "event_type",
    ["brain_thinking", "attack", "hit", "chain_start", "chain_step"],
)
def test_every_known_type_renders_valid_markup_with_full_data(event_type: str) -> None:
    data = {
        "vectors": [{"id": "v1", "reasoning": "r"}],
        "vector_id": "V-1",
        "finding_id": "F-1",
        "method": "GET",
        "endpoint": "/x",
        "confidence": "medium",
        "chain_id": "C-1",
        "level": 2,
    }
    out = render_detail(event_type, data)
    assert out
    _assert_valid_markup(out)
