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


class _CapturedFlowSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if method == "GET":
            return _Resp(200, "<html></html>")
        body = kwargs.get("json_data") or {}
        if path.endswith("/api/orders") and body.get("price") == 19.99:
            return _Resp(200, '{"ok":true,"order":"normal"}')
        if path.endswith("/api/orders") and body.get("price") == 0:
            return _Resp(200, '{"ok":true,"order":"mutated","price":0}')
        return _Resp(400, "invalid")


class _FakeSessionManager:
    def __init__(self, session: Any | None = None) -> None:
        self.session = session or _FakeSession()

    async def get_session(self, base_url: str, **kwargs: Any):
        return self.session


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


@pytest.mark.asyncio
async def test_business_logic_replays_captured_flow_with_value_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _FakeSessionManager(_CapturedFlowSession()),
    )
    monkeypatch.setattr(business_mod, "LOGIC_TESTS", [])

    result = await business_mod.execute(
        "https://app.example.test",
        captured_flows=[
            {
                "id": "req-1",
                "method": "POST",
                "path": "/api/orders",
                "body": '{"sku":"A1","quantity":1,"price":19.99}',
            }
        ],
    )

    assert result["vulnerable"] is True
    assert result["control_evidence"]["captured_flow_tests"][0]["source_request_id"] == "req-1"
    assert any("Captured flow mutation price" in item["evidence"] for item in result["findings"])
    price_finding = next(item for item in result["findings"] if "price" in item["evidence"])
    assert price_finding["control"]["paired_control"]["status"] == 200
