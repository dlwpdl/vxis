from __future__ import annotations

import importlib
import json
from typing import Any

import pytest

test_ssrf_mod = importlib.import_module("vxis.agent.skills.test_ssrf")


class _Resp:
    def __init__(self, status: int, text: str, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.text = text
        self.headers = headers or {}

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if "iam/security-credentials" in path or "iam%2Fsecurity-credentials" in path:
            return _Resp(
                200,
                json.dumps(
                    {
                        "AccessKeyId": "ASIA1234567890EXAMPLE",
                        "SecretAccessKey": "very-secret-key-material",
                        "Token": "session-token-material",
                        "Expiration": "2026-06-04T12:00:00Z",
                    }
                ),
            )
        return _Resp(200, "ok")


class _FakeSessionManager:
    async def get_session(self, base_url: str, **kwargs: Any):
        return _FakeSession()


@pytest.mark.asyncio
async def test_ssrf_extracts_and_redacts_cloud_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: _FakeSessionManager())

    result = await test_ssrf_mod.execute(
        "https://app.example.test/fetch?url=http://example.com",
        round=2,
    )

    assert result["vulnerable"] is True
    assert result["cloud_credentials"][0]["provider"] == "aws"
    assert result["cloud_credentials"][0]["has_secret_access_key"] is True
    assert result["findings"][0]["type"] == "ssrf_cloud_metadata_credentials"
    assert "very-secret-key-material" not in result["findings"][0]["response_preview"]
    assert "session-token-material" not in result["findings"][0]["response_preview"]
