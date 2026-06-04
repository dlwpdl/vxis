from __future__ import annotations

import importlib
from typing import Any

import pytest

from vxis.agent.skills import SKILL_REGISTRY
from vxis.agent.skills.execute_chain import execute

cloud_probe_mod = importlib.import_module("vxis.agent.cloud_probe")


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


@pytest.mark.asyncio
async def test_execute_chain_uses_post_auth_owned_object_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    async def fake_post_auth(target_url: str, token: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "accessible": [],
            "user_data_exposed": [],
            "identities": [
                {"name": "alice", "token": "tok-alice", "owned_ids": ["1001"]},
                {"name": "bob", "token": "tok-bob", "owned_ids": ["1002"]},
            ],
            "owner_map": {"1001": "alice", "1002": "bob"},
            "object_patterns": [
                {
                    "url_pattern": "https://app.example.test/api/orders/{id}",
                    "object_ids": ["1001", "1002"],
                    "owner_map": {"1001": "alice", "1002": "bob"},
                }
            ],
        }

    async def fake_idor(url_pattern: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
        calls.append({"url_pattern": url_pattern, "token": token, "kwargs": kwargs})
        return {
            "vulnerable": True,
            "url_pattern": url_pattern,
            "cross_identity_access": [
                {
                    "id": "1002",
                    "requester": "alice",
                    "expected_owner": "bob",
                    "status": 200,
                    "size": 91,
                }
            ],
            "auth_bypass_ids": [],
            "control_evidence": {"cross_identity_access": [{"id": "1002"}]},
            "identity_comparisons": [{"id": "1002"}],
            "total_tested": 2,
        }

    async def fake_auth_deep(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
        return {"findings": []}

    monkeypatch.setitem(SKILL_REGISTRY["post_auth_enum"], "fn", fake_post_auth)
    monkeypatch.setitem(SKILL_REGISTRY["test_idor"], "fn", fake_idor)
    monkeypatch.setitem(SKILL_REGISTRY["test_auth_deep"], "fn", fake_auth_deep)

    result = await execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[
            {"name": "alice", "token": "tok-alice"},
            {"name": "bob", "token": "tok-bob"},
        ],
    )

    assert result["ok"] is True
    assert calls[0]["url_pattern"].endswith("/api/orders/{id}")
    assert calls[0]["kwargs"]["object_ids"] == ["1001", "1002"]
    assert calls[0]["kwargs"]["owner_map"]["1002"] == "bob"
    assert any(finding["finding_type"] == "bola" for finding in result["findings"])


@pytest.mark.asyncio
async def test_execute_chain_ssrf_to_cloud_impact_template(
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
            "findings": [],
        }

    monkeypatch.setitem(SKILL_REGISTRY["test_ssrf"], "fn", fake_ssrf)

    result = await execute(
        "https://app.example.test",
        template="ssrf_to_cloud_impact",
        url="https://app.example.test/fetch?url=http://example.com",
    )

    assert result["ok"] is True
    assert "cloud_impact" in result["context_keys"]
    assert any(finding["finding_type"] == "ssrf_cloud_impact" for finding in result["findings"])


@pytest.mark.asyncio
async def test_cloud_impact_probe_runs_when_explicitly_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(credentials: dict[str, str]) -> dict[str, Any]:
        assert credentials["access_key_id"] == "ASIAEXAMPLE"
        return {
            "sts": {
                "ok": True,
                "status": 200,
                "account": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/demo/i-1",
            },
            "s3": {"ok": True, "status": 200, "bucket_count_observed": 2},
        }

    monkeypatch.setattr(cloud_probe_mod, "probe_aws_identity_and_storage", fake_probe)

    result = await execute(
        "https://app.example.test",
        steps=[
            {
                "skill": "prove_cloud_impact",
                "params": {
                    "allow_probe": True,
                    "cloud_credentials": [
                        {
                            "provider": "aws",
                            "fields": ["AccessKeyId", "SecretAccessKey", "Token"],
                            "access_key_id_raw": "ASIAEXAMPLE",
                            "secret_access_key": "secret",
                            "session_token": "session",
                        }
                    ],
                },
            }
        ],
    )

    impact = result["steps"][0]["data"]["cloud_impact"]
    assert impact["verified"] is True
    assert impact["reason"] == "verified_with_sts"
    assert impact["sts"]["account"] == "123456789012"
