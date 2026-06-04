from __future__ import annotations

from typing import Any

import pytest

from vxis.agent.skills import SKILL_REGISTRY
from vxis.agent.skills.execute_chain import execute


@pytest.mark.asyncio
async def test_execute_chain_extracts_context_and_normalizes_idor_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    async def fake_auth(target_url: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"skill": "attempt_auth", "target_url": target_url, "kwargs": kwargs})
        return {"authenticated": True, "token": "tok-alice", "method": "fixture"}

    async def fake_idor(url_pattern: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
        calls.append(
            {
                "skill": "test_idor",
                "url_pattern": url_pattern,
                "token": token,
                "kwargs": kwargs,
            }
        )
        return {
            "vulnerable": True,
            "url_pattern": url_pattern,
            "cross_identity_access": [
                {
                    "id": 2,
                    "requester": "alice",
                    "expected_owner": "bob",
                    "status": 200,
                    "size": 72,
                }
            ],
            "auth_bypass_ids": [],
            "control_evidence": {"cross_identity_access": [{"id": 2}]},
            "identity_comparisons": [{"id": 2, "principals": {"alice": {"status": 200}}}],
        }

    monkeypatch.setitem(SKILL_REGISTRY["attempt_auth"], "fn", fake_auth)
    monkeypatch.setitem(SKILL_REGISTRY["test_idor"], "fn", fake_idor)

    result = await execute(
        "https://app.example.test",
        steps=[
            {"skill": "attempt_auth", "extract": {"token": "token"}},
            {
                "skill": "test_idor",
                "params": {
                    "token": "{{token}}",
                    "url_pattern": "https://app.example.test/api/users/{id}",
                    "identities": "{{identities}}",
                },
            },
        ],
        identities=[
            {"name": "alice", "token": "{{token}}", "owned_ids": [1]},
            {"name": "bob", "token": "tok-bob", "owned_ids": [2]},
        ],
    )

    assert result["ok"] is True
    assert result["finding_count"] == 1
    assert result["findings"][0]["finding_type"] == "bola"
    assert calls[1]["token"] == "tok-alice"
    assert calls[1]["kwargs"]["identities"][0]["token"] == "tok-alice"


@pytest.mark.asyncio
async def test_execute_chain_skips_step_when_required_context_missing() -> None:
    result = await execute(
        "https://app.example.test",
        steps=[
            {"skill": "post_auth_enum", "requires": ["token"], "params": {"token": "{{token}}"}},
        ],
    )

    assert result["ok"] is True
    assert result["steps"][0]["skipped"] is True
    assert "missing context: token" in result["steps"][0]["summary"]


@pytest.mark.asyncio
async def test_execute_chain_auto_extracts_cloud_loot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_ssrf(url: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "vulnerable": True,
            "url": url,
            "cloud_credentials": [
                {
                    "provider": "aws",
                    "fields": ["AccessKeyId", "SecretAccessKey", "Token"],
                    "access_key_id": "ASIA12...[redacted]",
                    "has_secret_access_key": True,
                    "has_session_token": True,
                }
            ],
            "cloud_metadata": [{"provider": "aws", "fields": ["AccessKeyId"]}],
            "findings": [
                {
                    "type": "ssrf_cloud_metadata_credentials",
                    "severity": "critical",
                    "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "cloud_credentials": {
                        "provider": "aws",
                        "fields": ["AccessKeyId", "SecretAccessKey", "Token"],
                    },
                }
            ],
        }

    monkeypatch.setitem(SKILL_REGISTRY["test_ssrf"], "fn", fake_ssrf)

    result = await execute(
        "https://app.example.test",
        steps=[
            {
                "skill": "test_ssrf",
                "params": {"url": "https://app.example.test/fetch?url=http://example.com"},
            }
        ],
    )

    assert result["ok"] is True
    assert "cloud_credentials" in result["context_keys"]
    assert result["finding_count"] == 1
    assert result["findings"][0]["finding_type"] == "ssrf_cloud_metadata"
