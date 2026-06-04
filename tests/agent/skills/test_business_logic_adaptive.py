from __future__ import annotations

import importlib
from typing import Any

import pytest

business_mod = importlib.import_module("vxis.agent.skills.test_business_logic")


class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self.text = text

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if method == "GET":
            return _Resp(200, "<script>fetch('/api/cart/items')</script>")
        body = kwargs.get("json_data") or {}
        if path.endswith("/api/cart/items") and body.get("quantity") == 1 and "price" not in body:
            return _Resp(200, '{"ok":true,"mode":"control"}')
        if path.endswith("/api/cart/items") and body.get("quantity") == -1:
            return _Resp(200, '{"ok":true,"quantity":-1}')
        if path.endswith("/api/cart/items") and body.get("price") == 0:
            return _Resp(200, '{"ok":true,"price":0}')
        return _Resp(404, "not found")


class _FakeSessionManager:
    async def get_session(self, base_url: str, **kwargs: Any):
        return _FakeSession()


@pytest.mark.asyncio
async def test_business_logic_builds_dynamic_tests_from_discovered_flows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: _FakeSessionManager())
    monkeypatch.setattr(business_mod, "LOGIC_TESTS", [])

    result = await business_mod.execute("https://app.example.test")

    assert result["vulnerable"] is True
    assert any("Discovered cart" in item["evidence"] for item in result["findings"])
    assert result["control_evidence"]["discovered_tests"]
    assert result["findings"][0]["control"]["paired_control"]["status"] == 200
