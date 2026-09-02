from __future__ import annotations

import base64
import importlib
import json
from typing import Any

import pytest

attempt_auth_mod = importlib.import_module("vxis.agent.skills.attempt_auth")


def _jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}

    def part(data: dict[str, Any]) -> str:
        raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{part(header)}.{part(payload)}.sig"


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
        if email == "baseline-check@example.invalid":
            return _Resp(401, text="invalid credentials")
        if email == "alice@example.test":
            return _Resp(
                200,
                {
                    "authentication": {
                        "token": "tok-alice-12345678901234567890",  # gitleaks:allow -- test token
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
                        "token": "tok-bob-12345678901234567890",  # gitleaks:allow -- test token
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
    caplog: pytest.LogCaptureFixture,
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

    persisted_evidence = json.dumps(
        {
            "all_attempts": result["all_attempts"],
            "control_checks": result["control_checks"],
            "credentials_used": result["credentials_used"],
            "poc_http_exchange": result["poc_http_exchange"],
        }
    )
    for secret in (
        "alice-pass",
        "bob-pass",
        "tok-alice-12345678901234567890",
        "tok-bob-12345678901234567890",
    ):
        assert secret not in persisted_evidence
        assert secret not in caplog.text


class _ProbePrefersRealLoginSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        email = (kwargs.get("json_data") or {}).get("email", "")
        if method == "POST" and path == "/rest/user/login":
            return _Resp(405, text="method not allowed")
        if method == "POST" and path == "/login" and email == "x":
            return _Resp(401, text="login required")
        if method == "POST" and path == "/login" and email == "baseline-check@example.invalid":
            return _Resp(401, text="invalid credentials")
        if method == "POST" and path == "/login" and email == "alice@example.test":
            return _Resp(
                200,
                {
                    "authentication": {
                        "token": "tok-alice-12345678901234567890",  # gitleaks:allow -- test token
                        "email": email,
                        "role": "user",
                        "id": 1,
                    }
                },
            )
        return _Resp(401, text="invalid credentials")


class _ProbePrefersRealLoginManager:
    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _ProbePrefersRealLoginSession()


@pytest.mark.asyncio
async def test_attempt_auth_does_not_stop_on_405_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _ProbePrefersRealLoginManager(),
    )
    monkeypatch.setattr(attempt_auth_mod, "LOGIN_PATHS", ["/rest/user/login", "/login"])
    monkeypatch.setattr(attempt_auth_mod, "SQLI_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "DEFAULT_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "RESET_PATHS", [])

    result = await attempt_auth_mod.execute(
        "https://app.example.test",
        credentials=[{"email": "alice@example.test", "password": "alice-pass"}],
    )

    assert result["authenticated"] is True
    assert result["login_endpoint"] == "/login"


class _AssetDerivedLoginSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        email = (kwargs.get("json_data") or {}).get("email", "")
        if method == "GET" and path == "/":
            return _Resp(
                200,
                text='<html><script src="/static/js/main.js"></script></html>',
            )
        if method == "GET" and path == "/static/js/main.js":
            return _Resp(
                200,
                text='const svc="identity/";const routes={LOGIN:"api/auth/login"};',
            )
        if method == "POST" and path == "/rest/user/login":
            return _Resp(405, text="method not allowed")
        if method == "POST" and path == "/api/auth/login":
            return _Resp(404, text="not found")
        if method == "POST" and path == "/identity/api/auth/login" and email == "x":
            return _Resp(401, text="login required")
        if (
            method == "POST"
            and path == "/identity/api/auth/login"
            and email == "baseline-check@example.invalid"
        ):
            return _Resp(401, text="invalid credentials")
        if method == "POST" and path == "/identity/api/auth/login" and email == "alice@example.test":
            return _Resp(
                200,
                {
                    "authentication": {
                        "token": "tok-alice-12345678901234567890",  # gitleaks:allow -- test token
                        "email": email,
                        "role": "user",
                        "id": 1,
                    }
                },
            )
        return _Resp(404, text="not found")


class _AssetDerivedLoginManager:
    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _AssetDerivedLoginSession()


@pytest.mark.asyncio
async def test_attempt_auth_discovers_prefixed_login_from_js_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _AssetDerivedLoginManager(),
    )
    monkeypatch.setattr(attempt_auth_mod, "LOGIN_PATHS", ["/rest/user/login", "/api/auth/login"])
    monkeypatch.setattr(attempt_auth_mod, "SQLI_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "DEFAULT_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "RESET_PATHS", [])

    result = await attempt_auth_mod.execute(
        "https://app.example.test",
        credentials=[{"email": "alice@example.test", "password": "alice-pass"}],
    )

    assert result["authenticated"] is True
    assert result["login_endpoint"] == "/identity/api/auth/login"


class _PublicSignupSession:
    def __init__(self) -> None:
        self.accounts: list[dict[str, str]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        body = dict(kwargs.get("json_data") or {})
        email = str(body.get("email") or "")
        password = str(body.get("password") or "")
        username = str(body.get("username") or "")

        if method == "GET" and path == "/":
            return _Resp(200, text='<html><script src="/static/js/main.js"></script></html>')
        if method == "GET" and path == "/static/js/main.js":
            return _Resp(
                200,
                text='const svc="identity/";const routes={LOGIN:"api/auth/login",SIGNUP:"api/auth/signup"};',
            )
        if method == "POST" and path == "/rest/user/login":
            return _Resp(405, text="method not allowed")
        if method == "POST" and path == "/api/auth/login":
            return _Resp(404, text="not found")
        if method == "POST" and path == "/identity/api/auth/signup":
            if not body.get("name") or not body.get("number"):
                return _Resp(400, text="name and number required")
            self.accounts.append(
                {
                    "email": email,
                    "password": password,
                    "username": username,
                    "role": "user",
                }
            )
            return _Resp(200, text=json.dumps({"message": "registered"}))
        if method == "POST" and path == "/identity/api/auth/login" and email == "x":
            return _Resp(401, text="login required")
        if (
            method == "POST"
            and path == "/identity/api/auth/login"
            and email == "baseline-check@example.invalid"
        ):
            return _Resp(401, text="invalid credentials")
        if method == "POST" and path == "/identity/api/auth/login":
            account = next(
                (
                    item
                    for item in self.accounts
                    if email == item["email"] and password == item["password"]
                ),
                None,
            )
            if account:
                account_id = str(self.accounts.index(account) + 1)
                return _Resp(
                    200,
                    {
                        "token": f"tok-signed-up-{account_id}-12345678901234567890",  # gitleaks:allow -- test token
                        "email": account["email"],
                        "role": account["role"],
                        "id": int(account_id),
                    },
                )
            return _Resp(401, text="invalid credentials")
        return _Resp(404, text="not found")


class _PublicSignupManager:
    def __init__(self) -> None:
        self.session = _PublicSignupSession()

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return self.session


@pytest.mark.asyncio
async def test_attempt_auth_uses_public_signup_as_low_priv_foothold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _PublicSignupManager()
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: manager,
    )
    monkeypatch.setattr(attempt_auth_mod, "LOGIN_PATHS", ["/rest/user/login", "/api/auth/login"])
    monkeypatch.setattr(attempt_auth_mod, "SQLI_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "DEFAULT_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "RESET_PATHS", [])

    async def fake_discover_asset_auth_paths(session: Any) -> list[str]:
        return ["/identity/api/auth/login", "/identity/api/auth/signup"]

    monkeypatch.setattr(
        attempt_auth_mod,
        "_discover_asset_auth_paths",
        fake_discover_asset_auth_paths,
    )
    suffixes = iter(["aaaabbbb", "ccccdddd"])
    monkeypatch.setattr(attempt_auth_mod.secrets, "token_hex", lambda _: next(suffixes))

    result = await attempt_auth_mod.execute("https://app.example.test")

    assert result["authenticated"] is True
    assert result["method"] == "public_signup"
    assert result["login_endpoint"] == "/identity/api/auth/login"
    assert [item["email"] for item in result["identities"]] == [
        "aaaabbbb@example.test",
        "ccccdddd@example.test",
    ]
    assert [item["owned_ids"] for item in result["identities"]] == [["1"], ["2"]]
    assert result["owner_map"] == {"1": "aaaabbbb@example.test", "2": "ccccdddd@example.test"}


class _JwtOnlyLoginSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        email = (kwargs.get("json_data") or {}).get("email", "")
        if method == "POST" and path == "/login" and email == "x":
            return _Resp(401, text="login required")
        if method == "POST" and path == "/login" and email == "baseline-check@example.invalid":
            return _Resp(401, text="invalid credentials")
        if method == "POST" and path == "/login" and email == "alice@example.test":
            return _Resp(
                200,
                {
                    "token": _jwt(
                        {
                            "sub": "alice@example.test",
                            "role": "user",
                            "id": 7,
                        }
                    )
                },
            )
        return _Resp(401, text="invalid credentials")


class _JwtOnlyLoginManager:
    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _JwtOnlyLoginSession()


@pytest.mark.asyncio
async def test_attempt_auth_recovers_identity_from_token_only_jwt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _JwtOnlyLoginManager(),
    )
    monkeypatch.setattr(attempt_auth_mod, "LOGIN_PATHS", ["/login"])
    monkeypatch.setattr(attempt_auth_mod, "SQLI_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "DEFAULT_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "RESET_PATHS", [])

    result = await attempt_auth_mod.execute(
        "https://app.example.test",
        credentials=[{"email": "alice@example.test", "password": "alice-pass"}],
    )

    assert result["authenticated"] is True
    assert result["user_info"]["email"] == "alice@example.test"
    assert result["user_info"]["role"] == "user"
    assert str(result["user_info"]["id"]) == "7"
    assert result["identities"][0]["email"] == "alice@example.test"
    assert result["identities"][0]["role"] == "user"


class _ResetCandidateSession:
    def __init__(self) -> None:
        self.passwords = {"ops@example.test": "old-pass"}

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        body = dict(kwargs.get("json_data") or {})
        email = str(body.get("email") or "")
        password = str(body.get("password") or "")
        if method == "POST" and path == "/internal/auth/login" and email == "x":
            return _Resp(401, text="login required")
        if (
            method == "POST"
            and path == "/internal/auth/login"
            and email == "baseline-check@example.invalid"
        ):
            return _Resp(401, text="invalid credentials")
        if (
            method == "POST"
            and path == "/internal/auth/login"
            and email == "ops@example.test"
            and password == self.passwords["ops@example.test"]
        ):
            return _Resp(
                200,
                {
                    "authentication": {
                        "token": "tok-ops-12345678901234567890",  # gitleaks:allow -- test token
                        "email": email,
                        "role": "admin",
                        "id": 9,
                    }
                },
            )
        if method == "POST" and path == "/internal/auth/reset" and email == "test":
            return _Resp(400, text="need real account")
        if (
            method == "POST"
            and path == "/internal/auth/reset"
            and email == "ops@example.test"
            and body.get("answer") == "NCC-1701"
        ):
            self.passwords[email] = str(body.get("new") or "")
            return _Resp(200, text='{"message":"password updated"}')
        return _Resp(404, text="not found")


class _ResetCandidateManager:
    def __init__(self) -> None:
        self.session = _ResetCandidateSession()

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return self.session


@pytest.mark.asyncio
async def test_attempt_auth_uses_sensitive_file_reset_candidates_and_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _ResetCandidateManager(),
    )
    monkeypatch.setattr(attempt_auth_mod, "LOGIN_PATHS", ["/rest/user/login"])
    monkeypatch.setattr(attempt_auth_mod, "SQLI_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "DEFAULT_CREDS", [])
    monkeypatch.setattr(attempt_auth_mod, "RESET_PATHS", [])
    monkeypatch.setattr(
        attempt_auth_mod.secrets,
        "token_hex",
        lambda _: "abcdef123456",
    )

    result = await attempt_auth_mod.execute(
        "https://app.example.test",
        login_paths=["/internal/auth/login"],
        reset_paths=["/internal/auth/reset"],
        reset_candidates=[{"email": "ops@example.test", "answer": "NCC-1701"}],
    )

    assert result["authenticated"] is True
    assert result["method"] == "password_reset"
    assert result["login_endpoint"] == "/internal/auth/login"
    assert result["reset_endpoint"] == "/internal/auth/reset"
    assert result["token"] == "tok-ops-12345678901234567890"
