from __future__ import annotations

import importlib
import json
from typing import Any

import pytest

attempt_auth_mod = importlib.import_module("vxis.agent.skills.attempt_auth")


class _Raw:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def json(self) -> dict[str, Any]:
        return self._data


class _Resp:
    def __init__(self, status: int, data: dict[str, Any] | None = None, text: str = "") -> None:
        self.status = status
        self._data = data or {}
        self.text = text or json.dumps(self._data)
        self.response = _Raw(self._data)

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        email = (kwargs.get("json_data") or {}).get("email", "")
        if method == "POST" and path == "/login" and email == "x":
            return _Resp(401, text="login required")
        if email == "vxis-negative-control@example.invalid":
            return _Resp(401, text="invalid credentials")
        if email == "alice@example.test":
            return _Resp(
                200,
                {
                    "authentication": {
                        "token": "tok-alice-12345678901234567890",
                        "email": email,
                        "role": "user",
                        "id": 1,
                    }
                },
            )
        if email == "bob@example.test":
            return _Resp(
                200,
                {
                    "authentication": {
                        "token": "tok-bob-12345678901234567890",
                        "email": email,
                        "role": "user",
                        "id": 2,
                    }
                },
            )
        return _Resp(401, text="invalid credentials")


class _FakeSessionManager:
    def __init__(self) -> None:
        self.identities: list[str | None] = []

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        self.identities.append(identity)
        return _FakeSession(identity)


@pytest.mark.asyncio
async def test_attempt_auth_returns_multiple_authenticated_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _FakeSessionManager()
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)
    monkeypatch.setattr(attempt_auth_mod, "LOGIN_PATHS", ["/login"])
    monkeypatch.setattr(attempt_auth_mod, "SQLI_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "DEFAULT_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "RESET_PATHS", [])

    result = await attempt_auth_mod.execute(
        "https://app.example.test",
        credentials=[
            {
                "name": "alice",
                "email": "alice@example.test",
                "password": "alice-pass",
                "role": "user",
            },
            {
                "name": "bob",
                "email": "bob@example.test",
                "password": "bob-pass",
                "role": "user",
            },
        ],
    )

    assert result["authenticated"] is True
    assert result["token"] == "tok-alice-12345678901234567890"
    assert [item["name"] for item in result["identities"]] == ["alice", "bob"]
    assert result["owner_map"] == {"1": "alice", "2": "bob"}
    assert "operator_credentials:alice" in manager.identities
    assert "operator_credentials:bob" in manager.identities
