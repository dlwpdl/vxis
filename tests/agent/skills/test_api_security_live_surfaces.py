from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import json
from typing import Any

import pytest

test_api_security_mod = importlib.import_module("vxis.agent.skills.test_api_security")


@dataclass
class _Resp:
    status: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        parsed = urlparse(path)
        route = parsed.path or path

        if method == "POST" and route == "/graphql":
            return _Resp(
                200,
                json.dumps(
                    {
                        "data": {
                            "__schema": {
                                "queryType": {"name": "Query"},
                                "mutationType": {"name": "Mutation"},
                                "types": [
                                    {
                                        "name": "Query",
                                        "fields": [
                                            {"name": "users", "args": []},
                                            {"name": "user", "args": [{"name": "id"}]},
                                        ],
                                    }
                                ],
                            }
                        }
                    }
                ),
                {"content-type": "application/json"},
            )

        if method == "GET" and route == "/openapi.json":
            return _Resp(
                200,
                json.dumps(
                    {
                        "openapi": "3.0.0",
                        "info": {"title": "Fixture API"},
                        "servers": [{"url": "/api"}],
                        "paths": {
                            "/users": {"get": {"parameters": []}},
                            "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
                        },
                    }
                ),
                {"content-type": "application/json"},
            )

        if method == "GET" and route == "/api/users":
            return _Resp(
                200,
                json.dumps({"data": [{"id": 1, "email": "alice@example.test"}]}),
                {"content-type": "application/json"},
            )

        return _Resp(404, "not found")


class _FakeSessionManager:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session

    async def get_session(self, base_url: str, **kwargs: Any) -> _FakeSession:
        return self.session


@pytest.mark.asyncio
async def test_api_security_discovers_graphql_and_openapi_live_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute("https://app.example.test")

    types = {finding["type"] for finding in result["findings"]}
    assert "graphql_introspection_enabled" in types
    assert "openapi_schema_exposed" in types
    assert "openapi_unauthenticated_data_endpoint" in types
    assert any(call["path"] == "https://app.example.test/api/users" for call in session.calls)
