from __future__ import annotations

from dataclasses import dataclass
import importlib
from typing import Any

import pytest

test_idor_mod = importlib.import_module("vxis.agent.skills.test_idor")


@dataclass
class _Resp:
    status: int
    text: str

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity or "default"
        self.calls: list[dict[str, Any]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        obj_id = path.rstrip("/").rsplit("/", 1)[-1]
        identity = self.identity
        if identity == "anonymous":
            return _Resp(401, "login required")
        if identity == "alice" and obj_id in {"1", "2"}:
            owner = "alice" if obj_id == "1" else "bob"
            return _Resp(200, f'{{"id":{obj_id},"owner":"{owner}","email":"{owner}@example.test"}}')
        if identity == "bob" and obj_id == "2":
            return _Resp(200, '{"id":2,"owner":"bob","email":"bob@example.test"}')
        return _Resp(403, "forbidden")


class _FakeSessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, _FakeSession] = {}
        self.identities: list[str | None] = []

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        self.identities.append(identity)
        key = identity or "default"
        if key not in self.sessions:
            self.sessions[key] = _FakeSession(identity)
        return self.sessions[key]


@pytest.mark.asyncio
async def test_idor_detects_cross_identity_bola(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _FakeSessionManager()
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_idor_mod.execute(
        "https://app.example.test/api/users/{id}",
        identities=[
            {"name": "alice", "token": "tok-alice", "owned_ids": [1], "role": "user"},
            {"name": "bob", "token": "tok-bob", "owned_ids": [2], "role": "user"},
        ],
        object_ids=[1, 2],
    )

    assert result["vulnerable"] is True
    assert "anonymous" in manager.identities
    assert "alice" in manager.identities
    assert "bob" in manager.identities
    assert any(
        item["requester"] == "alice"
        and item["expected_owner"] == "bob"
        and item["id"] == 2
        for item in result["cross_identity_access"]
    )
    assert result["auth_bypass_ids"] == []


@pytest.mark.asyncio
async def test_idor_detects_role_matrix_denied_id(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _FakeSessionManager()
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_idor_mod.execute(
        "https://app.example.test/api/admin/users/{id}",
        identities=[
            {
                "name": "alice",
                "token": "tok-alice",
                "role": "user",
                "denied_ids": [2],
            }
        ],
        object_ids=[2],
        include_anonymous=False,
    )

    assert result["vulnerable"] is True
    assert result["role_matrix_findings"][0]["requester"] == "alice"
    assert result["role_matrix_findings"][0]["expected"] == "deny"
