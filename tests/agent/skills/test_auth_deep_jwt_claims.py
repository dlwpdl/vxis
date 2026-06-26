from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import json
from typing import Any
from urllib.parse import urlparse

import pytest

test_auth_deep_mod = importlib.import_module("vxis.agent.skills.test_auth_deep")


@dataclass
class _Resp:
    status: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self, original_token: str) -> None:
        self.original_token = original_token
        self.calls: list[dict[str, Any]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        if method != "GET" or route != "/api/users/me":
            return _Resp(404, "not found")

        token = str(kwargs.get("headers", {}).get("Authorization", "")).removeprefix("Bearer ")
        if token == self.original_token:
            return _Resp(200, json.dumps({"sub": "1", "role": "user"}))

        parts = token.split(".")
        if len(parts) == 3 and parts[2] == "":
            header = test_auth_deep_mod._decode_jwt_json(parts[0])
            payload = test_auth_deep_mod._decode_jwt_json(parts[1])
            if header.get("alg") == "none" and payload.get("role") == "admin":
                return _Resp(200, json.dumps({"sub": "1", "role": "admin", "admin": True}))

        return _Resp(401, "unauthorized")


class _FakeSessionManager:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session

    async def get_session(self, base_url: str, **kwargs: Any) -> _FakeSession:
        return self.session


def _jwt(header: dict[str, Any], payload: dict[str, Any], signature: str = "sig") -> str:
    return (
        f"{test_auth_deep_mod._jwt_json_part(header)}."
        f"{test_auth_deep_mod._jwt_json_part(payload)}."
        f"{signature}"
    )


@pytest.mark.asyncio
async def test_jwt_claim_tampering_requires_protected_endpoint_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"})
    session = _FakeSession(token)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: _FakeSessionManager(session))
    monkeypatch.setattr(test_auth_deep_mod, "JWT_ALG_NONE_HEADERS", [{"alg": "none", "typ": "JWT"}])
    monkeypatch.setattr(test_auth_deep_mod, "RESET_PATHS", [])

    result = await test_auth_deep_mod.execute("https://app.example.test", token=token)

    finding = next(item for item in result["findings"] if item["type"] == "jwt_claim_tampering")
    assert finding["severity"] == "critical"
    assert finding["control"]["original_claims"]["role"] == "user"
    assert finding["control"]["tampered_claims"]["role"] == "admin"
    assert "protected" in finding["evidence"].lower() or finding["control"]["forged_status"] == 200
    assert token not in json.dumps(finding)
