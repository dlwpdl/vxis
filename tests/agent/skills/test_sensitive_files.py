from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any

import pytest

test_sensitive_files_mod = importlib.import_module("vxis.agent.skills.test_sensitive_files")


@dataclass
class _Resp:
    status: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def body_length(self) -> int:
        return len(self.text.encode("utf-8", "ignore"))


class _FakeSessionManager:
    def __init__(self, session: Any) -> None:
        self.session = session

    async def get_session(self, base_url: str, **kwargs: Any) -> Any:
        return self.session


class _DirectoryMiningSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        route = urlparse(path).path or path
        if method != "GET":
            return _Resp(405, "nope")
        if route == "/definitely-not-real-probe":
            return _Resp(404, "not found")
        if route == "/ftp/":
            return _Resp(
                200,
                """
                <html><title>listing directory /ftp/</title>
                <a href=".">.</a>
                <a href="credentials.txt">credentials.txt</a>
                <a href="package.json.bak">package.json.bak</a>
                <a href="incident-support.kdbx">incident-support.kdbx</a>
                </html>
                """,
            )
        if route == "/ftp/credentials.txt":
            return _Resp(
                200,
                "email=admin@example.test\npassword=Sup3rSecret!\n",
            )
        if route == "/ftp/.env":
            return _Resp(
                200,
                "ADMIN_EMAIL=seed-admin@example.test\nADMIN_PASSWORD=FromNestedEnv2026!\n",
            )
        if route == "/ftp/package.json.bak":
            return _Resp(
                200,
                '{"name":"app","scripts":{"start":"node server.js"},"authUrl":"https://api.example.test/auth/login","internalLogin":"/rest/user/login","resetPath":"/rest/user/reset-password"}',
            )
        if route == "/ftp/incident-support.kdbx":
            return _Resp(200, "KDBX\x00vault-bytes")
        if route == "/support/logs":
            return _Resp(
                200,
                """
                <html><title>listing directory /support/logs</title>
                <a href="logs/access.log.2026-09-01">access.log.2026-09-01</a>
                <a href="audit.json">audit.json</a>
                </html>
                """,
            )
        if route == "/support/logs/access.log.2026-09-01":
            return _Resp(
                200,
                'POST /rest/user/login {"email":"ops@example.test","password":"Winter2026!"}',
            )
        if route == "/support/logs/audit.json":
            return _Resp(
                200,
                '{"auditFilename":"logs/audit.json","files":[{"name":"/juice-shop/logs/access.log.2026-09-01"}],"email":"ops@example.test","securityAnswer":"NCC-1701"}',
            )
        if route == "/encryptionkeys/":
            return _Resp(
                200,
                """
                <html><title>listing directory /encryptionkeys/</title>
                <a href="jwt.pub">jwt.pub</a>
                <a href="premium.key">premium.key</a>
                </html>
                """,
            )
        if route == "/encryptionkeys/jwt.pub":
            return _Resp(200, "-----BEGIN RSA PUBLIC KEY-----\nabc\n-----END RSA PUBLIC KEY-----")
        if route == "/encryptionkeys/premium.key":
            return _Resp(200, "1337133713371337.EA99A61D92D2955B1E9285B55BF2AD42")
        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_sensitive_files_mines_directory_children_into_pivots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _DirectoryMiningSession()
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: _FakeSessionManager(session))

    result = await test_sensitive_files_mod.execute("https://app.example.test")

    credentials = result.get("credentials") or []
    seed_paths = result.get("seed_paths") or []
    loot = result.get("loot") or []
    urls = result.get("urls") or []
    login_paths = result.get("login_paths") or []
    reset_paths = result.get("reset_paths") or []
    reset_candidates = result.get("reset_candidates") or []

    assert any(item.get("email") == "admin@example.test" and item.get("password") == "Sup3rSecret!" for item in credentials)
    assert any(item.get("email") == "seed-admin@example.test" and item.get("password") == "FromNestedEnv2026!" for item in credentials)
    assert any(item.get("email") == "ops@example.test" and item.get("password") == "Winter2026!" for item in credentials)
    assert "/ftp/credentials.txt" in seed_paths
    assert "/support/logs/access.log.2026-09-01" in seed_paths
    assert "/support/logs/audit.json" in seed_paths
    assert any(item.get("kind") == "artifact" and item.get("path") == "/ftp/incident-support.kdbx" for item in loot)
    assert any(item.get("kind") == "secret" and item.get("path") == "/encryptionkeys/premium.key" for item in loot)
    assert "https://api.example.test/auth/login" in urls
    assert "/rest/user/login" in login_paths
    assert "/rest/user/reset-password" in reset_paths
    assert any(
        item.get("email") == "ops@example.test" and item.get("answer") == "NCC-1701"
        for item in reset_candidates
    )
