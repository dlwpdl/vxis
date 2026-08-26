from __future__ import annotations

import inspect

import pytest

from vxis.cli import main


@pytest.mark.asyncio
async def test_build_scan_approval_callbacks_uses_console_callbacks(monkeypatch) -> None:
    calls: list[tuple[str, object, object]] = []

    async def fake_injection(display, summary):
        calls.append(("injection", display, summary))
        return "readonly"

    async def fake_approval(display, actions):
        calls.append(("approval", display, actions))
        return [True]

    monkeypatch.setattr(main, "_console_injection_gate", fake_injection)
    monkeypatch.setattr(main, "_console_deferred_approval", fake_approval)

    injection_cb, approval_cb = main._build_scan_approval_callbacks(
        display="live",
        tui_mode=False,
        tui_app=None,
    )

    assert await injection_cb({"target": "http://x"}) == "readonly"
    assert await approval_cb(["action-1"]) == [True]
    assert calls == [
        ("injection", "live", {"target": "http://x"}),
        ("approval", "live", ["action-1"]),
    ]


@pytest.mark.asyncio
async def test_build_scan_approval_callbacks_uses_tui_callbacks(monkeypatch) -> None:
    calls: list[tuple[str, object, object]] = []

    async def fake_injection(tui_app, summary):
        calls.append(("injection", tui_app, summary))
        return "full"

    async def fake_approval(tui_app, actions):
        calls.append(("approval", tui_app, actions))
        return [False]

    monkeypatch.setattr(main, "_tui_injection_gate", fake_injection)
    monkeypatch.setattr(main, "_tui_deferred_approval", fake_approval)

    injection_cb, approval_cb = main._build_scan_approval_callbacks(
        display="ignored",
        tui_mode=True,
        tui_app="tui",
    )

    assert await injection_cb({"target": "http://x"}) == "full"
    assert await approval_cb(["action-1"]) == [False]
    assert calls == [
        ("injection", "tui", {"target": "http://x"}),
        ("approval", "tui", ["action-1"]),
    ]


def test_scan_delegates_approval_wiring_outside_scan() -> None:
    source = inspect.getsource(main.scan)

    assert "_build_scan_approval_callbacks(" in source
    assert "InjectionModeScreen" not in source
    assert "ActionApprovalScreen" not in source


def test_scan_no_longer_references_interactive_brain() -> None:
    assert "InteractiveBrain" not in inspect.getsource(main.scan)
