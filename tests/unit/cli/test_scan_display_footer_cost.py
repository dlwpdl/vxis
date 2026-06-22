"""The Rich-Live footer must show cost at a glance, next to elapsed/tokens.

The footer (ScanLiveDisplay._render_footer) showed Elapsed / Current / Tokens
but not cost — so on the Rich fallback display the operator could not see spend.
Cost is added next to tokens (the Textual TUI footer already carries it).
"""

from __future__ import annotations

from rich.console import Console

from vxis.cli.scan_display import ScanLiveDisplay


def _display() -> ScanLiveDisplay:
    return ScanLiveDisplay(
        Console(), target="http://localhost:3000", profile="standard",
        brain="claude", ghost=False, version="0.2.0",
    )


def test_footer_shows_cost_when_telemetry_present():
    d = _display()
    d.telemetry = {"total_tokens": 12000, "cost_usd": 0.1234}
    text = str(d._render_footer().renderable)
    assert "Cost" in text
    assert "0.1234" in text
    assert "Tokens" in text  # still there, cost sits alongside


def test_footer_marks_estimated_cost():
    d = _display()
    d.telemetry = {"total_tokens": 5000, "cost_usd": 0.05, "cost_estimated": True}
    text = str(d._render_footer().renderable)
    assert "est." in text


def test_footer_without_telemetry_has_no_cost():
    d = _display()  # telemetry defaults to {}
    text = str(d._render_footer().renderable)
    assert "Cost" not in text
    assert "Elapsed" in text
