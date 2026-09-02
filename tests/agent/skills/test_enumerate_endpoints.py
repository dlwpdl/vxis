from __future__ import annotations

from dataclasses import dataclass, field
import importlib
from typing import Any

import pytest

enumerate_endpoints = importlib.import_module("vxis.agent.skills.enumerate_endpoints")


@dataclass
class _Resp:
    status: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self, responses: dict[str, _Resp]) -> None:
        self._responses = responses

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        del method, kwargs
        return self._responses.get(path, _Resp(404, "not found"))


class _FakeSessionManager:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session

    async def get_session(self, base_url: str, **kwargs: Any) -> _FakeSession:
        del base_url, kwargs
        return self.session


@pytest.mark.asyncio
async def test_enumerate_endpoints_suppresses_known_noisy_500s(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession(
        {
            "/definitely-not-real-xyz-probe": _Resp(404, "not found"),
            "/rest": _Resp(500, "Error: Unexpected path: /rest"),
            "/profile": _Resp(500, "Error: Blocked illegal activity by ::1"),
            "/redirect": _Resp(
                500,
                "TypeError: Cannot read properties of undefined (reading 'includes')",
            ),
            "/api/error": _Resp(500, "Internal Server Error"),
        }
    )
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager", lambda: _FakeSessionManager(session)
    )
    monkeypatch.setattr(
        enumerate_endpoints,
        "COMMON_PATHS",
        ["/rest", "/profile", "/redirect", "/api/error"],
    )

    result = await enumerate_endpoints.execute("https://app.example.test")

    errors = {item["path"]: item for item in result["errors"]}
    assert set(errors) == {"/redirect", "/api/error"}
    assert errors["/redirect"]["error_kind"] == "actionable"
    assert errors["/api/error"]["error_kind"] == "unknown"

    noise_errors = {item["path"]: item for item in result["noise_errors"]}
    assert set(noise_errors) == {"/rest", "/profile"}
    assert noise_errors["/rest"]["error_kind"] == "unexpected_path"
    assert noise_errors["/profile"]["error_kind"] == "illegal_activity_block"
