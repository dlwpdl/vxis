from __future__ import annotations

import io
from types import SimpleNamespace

from rich.console import Console

from vxis.cli.scan_display import ScanLiveDisplay


def test_scan_display_switches_to_single_loop_live_mode() -> None:
    console = Console(file=io.StringIO(), force_terminal=False, width=120)
    display = ScanLiveDisplay(
        console,
        target="https://example.test",
        profile="standard",
        brain="test-brain",
        ghost=False,
        version="0.0.0",
    )
    display.init_phases(
        [
            SimpleNamespace(id=0, name="Foundation"),
            SimpleNamespace(id=1, name="Director"),
        ]
    )

    display.handle_event("phase_start", {"phase": "scan_loop", "name": "ScanAgentLoop"})
    display.handle_event(
        "brain_thinking",
        {
            "phase": "scan_loop",
            "iteration": 8,
            "max_iters": 50,
            "vectors": [{"id": "web:sqli", "reasoning": "testing login surface"}],
        },
    )
    display.handle_event(
        "hit",
        {
            "vector_id": "sql_injection",
            "severity": "critical",
            "level": 4,
            "title": "SQL Injection on login",
        },
    )
    display.handle_event(
        "control_plane",
        {
            "iteration": 8,
            "max_iters": 50,
            "waiting_reason": "Executing: browser_fill_form /login",
            "todo_counts": {"pending": 2, "done": 1},
            "branch_counts": {"active": 1, "proven": 1},
            "todos": [
                {"id": "web:auth-bypass", "title": "Authentication bypass or weak login", "priority": 95, "status": "pending"},
            ],
            "branches": [
                {
                    "id": "web:auth-bypass",
                    "vector_id": "WEB-AUTH-001",
                    "status": "active",
                    "attempts": 1,
                    "last_tool": "browser_fill_form",
                    "next_step": "Probe /admin and authenticated APIs with the new session",
                },
            ],
            "telemetry": {
                "provider": "openai",
                "model": "gpt-5.4-mini",
                "llm_calls": 3,
                "brain_decisions": 4,
                "total_tokens": 12345,
                "tokens_estimated": True,
                "cost_usd": 0.0123,
                "cost_estimated": True,
            },
            "proxy": {
                "backend": "xray",
                "running": True,
                "proxy_url": "http://localhost:8081",
                "flow_count": 7,
                "auth_flow_count": 2,
                "recent_requests": [
                    {"method": "POST", "path": "/login", "status_code": 302},
                    {"method": "GET", "path": "/admin", "status_code": 200},
                ],
            },
        },
    )

    assert display.loop_mode is True
    assert display.loop_iteration == 8
    assert display.loop_max_iters == 50
    assert display.total_findings == 1
    assert display.phases[0]["name"] == "Scan Loop"
    assert display.waiting_reason == "Executing: browser_fill_form /login"

    panel = display._render_phases()
    assert "Scan Loop" in str(panel.title)
    control_panel = display._render_control_plane()
    control_text = str(control_panel.renderable)
    assert "Control Plane" in str(control_panel.title)
    assert "gpt-5.4-mini" in control_text
    assert "Authentication bypass or weak login" in control_text
    assert "Probe /admin" in control_text
    assert "xray running" in control_text
    assert "/login" in control_text
