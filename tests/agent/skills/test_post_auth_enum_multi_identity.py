from __future__ import annotations

import importlib
from typing import Any

import pytest

post_auth_enum_mod = importlib.import_module("vxis.agent.skills.post_auth_enum")


class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self.text = text

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity or "anonymous"

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if self.identity == "anonymous":
            return _Resp(401, "login required")
        if path == "/api/Orders/":
            if self.identity == "alice":
                return _Resp(200, '[{"id":1001,"owner":"alice","total":25}]')
            if self.identity == "bob":
                return _Resp(200, '[{"id":1002,"owner":"bob","total":40}]')
        return _Resp(404, "not found")


class _FakeSessionManager:
    def __init__(self) -> None:
        self.identities: list[str | None] = []

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        self.identities.append(identity)
        return _FakeSession(identity)


@pytest.mark.asyncio
async def test_post_auth_enum_enriches_identities_with_owned_object_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _FakeSessionManager()
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", ["/api/Orders/"])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[
            {"name": "alice", "token": "tok-alice"},
            {"name": "bob", "token": "tok-bob"},
        ],
    )

    assert result["owner_map"]["1001"] == "alice"
    assert result["owner_map"]["1002"] == "bob"
    assert result["object_patterns"][0]["url_pattern"].endswith("/api/Orders/{id}")
    assert set(result["object_patterns"][0]["object_ids"]) == {"1001", "1002"}
    bob = next(item for item in result["identities"] if item["name"] == "bob")
    assert "1002" in bob["owned_ids"]
    assert "alice" in manager.identities
    assert "bob" in manager.identities
