from __future__ import annotations

import importlib
from typing import Any
from urllib.parse import unquote

import pytest

xss_mod = importlib.import_module("vxis.agent.skills.test_xss")


class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self.text = text

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _SourceMapSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if path.endswith("/app.js.map"):
            return _Resp(
                200,
                '{"version":3,"sources":["app.ts"],"sourcesContent":["const apiKey = \\"secret\\";"]}',
            )
        return _Resp(200, '<script src="/app.js"></script>')


class _ReflectingSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        return _Resp(200, f"<html><body>{unquote(path)}</body></html>")


class _FakeSessionManager:
    def __init__(self, session: Any) -> None:
        self.session = session

    async def get_session(self, base_url: str, **kwargs: Any):
        return self.session


@pytest.mark.asyncio
async def test_xss_reports_accessible_source_map_with_secret_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _FakeSessionManager(_SourceMapSession()),
    )
    monkeypatch.setattr(xss_mod, "_xss_payloads_for_round", lambda round: [])

    result = await xss_mod.execute("https://app.example.test/search?q=test")

    assert result["vulnerable"] is True
    assert result["findings"][0]["type"] == "client_side_source_map_exposure"
    assert result["findings"][0]["severity"] == "high"


@pytest.mark.asyncio
async def test_xss_browser_confirmation_upgrades_reflection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_browser_confirm(test_url: str, payload: str) -> dict[str, Any]:
        return {"attempted": True, "executed": True, "hits": [{"kind": "alert", "value": "1"}]}

    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _FakeSessionManager(_ReflectingSession()),
    )
    monkeypatch.setattr(
        xss_mod,
        "_xss_payloads_for_round",
        lambda round: [{"payload": "<script>alert(1)</script>", "context": "basic"}],
    )
    monkeypatch.setattr(xss_mod, "_browser_confirm_xss", fake_browser_confirm)

    result = await xss_mod.execute(
        "https://app.example.test/search?q=test",
        browser_confirm=True,
    )

    assert result["vulnerable"] is True
    assert result["findings"][0]["type"] == "xss_browser_confirmed_basic"
    assert result["findings"][0]["severity"] == "critical"
