from __future__ import annotations

from dataclasses import dataclass, field
import base64
import importlib
import json
from typing import Any

import pytest

test_api_security_mod = importlib.import_module("vxis.agent.skills.test_api_security")
surface_mod = importlib.import_module("vxis.agent.skills._api_security_surface_discovery")
crown_mod = importlib.import_module("vxis.agent.skills._api_security_crown")
parse_openapi = importlib.import_module("vxis.primitives.patterns").parse_openapi


def _jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    def part(data: dict[str, Any]) -> str:
        raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"{part(header)}.{part(payload)}.sig"


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


class _PrivilegedProbeSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        route = urlparse(path).path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")

        if method != "GET":
            return _Resp(405, "nope")

        if route == "/weak-admin":
            if not auth:
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            return _Resp(200, json.dumps({"ok": True, "scope": "shared"}), {"content-type": "application/json"})

        if route == "/real-admin":
            if not auth:
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if auth == "Bearer elevated":
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


class _ActionApiProbeSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        route = urlparse(path).path or path
        body = dict(kwargs.get("json_data") or {})

        if method != "POST" or route != "/admin/R":
            return _Resp(404, "not found")
        if body.get("action") != "SetUserRole":
            return _Resp(400, json.dumps({"error": "bad_action"}), {"content-type": "application/json"})
        if not body.get("token"):
            return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
        if body.get("token") == "elevated":
            return _Resp(200, json.dumps({"ok": True, "role": "admin"}), {"content-type": "application/json"})
        return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})


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


def test_parse_openapi_ignores_non_mapping_text() -> None:
    assert parse_openapi("<html><title>not a spec</title></html>") == {
        "version": "",
        "title": "",
        "base_path": "",
        "endpoints": [],
    }


def test_action_api_privileged_candidates_ignore_read_only_actions() -> None:
    candidates = surface_mod._extract_action_privileged_candidates(
        {
            "/admin/R": {"GetUserList", "SetUserRole", "DeleteUser"},
            "/profile/R": {"GetProfile"},
        }
    )

    actions = {candidate["json_body"]["action"] for candidate in candidates}
    assert "GetUserList" not in actions
    assert "SetUserRole" in actions
    assert "DeleteUser" in actions


def test_graphql_privileged_candidates_build_mutation_probe() -> None:
    schema = {
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Mutation",
                "fields": [
                    {
                        "name": "grantAdminRole",
                        "args": [
                            {
                                "name": "userId",
                                "type": {
                                    "kind": "NON_NULL",
                                    "name": None,
                                    "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None},
                                },
                            }
                        ],
                        "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                    }
                ],
            }
        ],
    }

    candidates = surface_mod._extract_graphql_privileged_candidates(schema, "/graphql")

    assert len(candidates) == 1
    assert candidates[0]["path"] == "/graphql"
    assert "mutation" in candidates[0]["json_body"]["query"]
    assert "grantAdminRole(userId: 1)" in candidates[0]["json_body"]["query"]


@pytest.mark.asyncio
async def test_privileged_probe_requires_low_priv_denial_when_baseline_exists() -> None:
    proof = await crown_mod._probe_privileged_access(
        _PrivilegedProbeSession(),
        target="https://app.example.test",
        elevated_token="elevated",
        baseline_token="baseline",
        candidate_paths=["/weak-admin", "/real-admin"],
    )

    assert proof["endpoint"] == "/real-admin"
    assert proof["baseline_status"] == 403
    assert proof["elevated_status"] == 200


@pytest.mark.asyncio
async def test_privileged_probe_supports_action_api_token_in_body() -> None:
    proof = await crown_mod._probe_privileged_access(
        _ActionApiProbeSession(),
        target="https://app.example.test",
        elevated_token="elevated",
        baseline_token="baseline",
        candidate_paths=[
            {
                "kind": "action_api",
                "path": "/admin/R",
                "method": "POST",
                "json_body": {"action": "SetUserRole", "data": {"userId": 1, "role": "admin"}},
                "inject_token_body": True,
            }
        ],
    )

    assert proof["endpoint"] == "/admin/R"
    assert proof["method"] == "POST"
    assert proof["baseline_status"] == 403
    assert proof["elevated_status"] == 200
    assert proof["json_body"]["action"] == "SetUserRole"


class _MassAssignmentSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.accounts: list[dict[str, str]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        parsed = urlparse(path)
        route = parsed.path or path
        body = dict(kwargs.get("json_data") or {})

        if method == "POST" and route == "/api/users":
            account = {
                "email": str(body.get("email") or ""),
                "password": str(body.get("password") or ""),
                "username": str(body.get("username") or ""),
                "role": str(body.get("role") or "user"),
            }
            self.accounts.append(account)
            return _Resp(
                201,
                json.dumps({"status": "success", "data": {"email": account["email"], "role": account["role"]}}),
                {"content-type": "application/json"},
            )

        if method == "POST" and route == "/rest/user/login":
            identity = str(body.get("email") or body.get("username") or "")
            password = str(body.get("password") or "")
            account = next(
                (
                    item
                    for item in self.accounts
                    if identity in {item.get("email", ""), item.get("username", "")}
                    and password == item.get("password", "")
                ),
                None,
            )
            if account:
                token = _jwt(
                    {
                        "email": account.get("email", ""),
                        "role": account.get("role", ""),
                        "sub": account.get("username", ""),
                    }
                )
                account["token"] = token
                return _Resp(
                    200,
                    json.dumps(
                        {
                            "authentication": {
                                "token": token
                            },
                            "user": {
                                "email": account.get("email", ""),
                                "role": account.get("role", ""),
                            },
                        }
                    ),
                    {"content-type": "application/json"},
                )
            return _Resp(401, json.dumps({"status": "error"}), {"content-type": "application/json"})

        if method == "GET" and route == "/admin/panel":
            auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
            if auth == "Bearer tok-foothold":
                return _Resp(200, json.dumps({"ok": True, "scope": "foothold"}), {"content-type": "application/json"})
            if any(
                auth == f"Bearer {item.get('token', '')}" and item.get("role") == "admin"
                for item in self.accounts
            ):
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


class _OpenApiPrivilegedMassAssignmentSession(_MassAssignmentSession):
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        parsed = urlparse(path)
        route = parsed.path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")

        if method == "GET" and route == "/openapi.json":
            return _Resp(
                200,
                json.dumps(
                    {
                        "openapi": "3.0.0",
                        "info": {"title": "Fixture API"},
                        "servers": [{"url": "/api"}],
                        "paths": {
                            "/admin/users/{id}/role": {
                                "post": {
                                    "parameters": [{"name": "id", "in": "path", "required": True}]
                                }
                            }
                        },
                    }
                ),
                {"content-type": "application/json"},
            )

        if method == "POST" and route == "/api/admin/users/1/role":
            if not auth:
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if any(
                auth == f"Bearer {item.get('token', '')}" and item.get("role") == "admin"
                for item in self.accounts
            ):
                return _Resp(200, json.dumps({"ok": True, "role": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return await super().request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_api_security_returns_credential_evidence_for_privileged_mass_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _MassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    assert mass["endpoint"] == "/api/users"
    assert mass["credential_evidence"]["login_endpoint"] == "/rest/user/login"
    assert mass["credential_evidence"]["persisted_role"] == "admin"
    assert mass["credential_evidence"]["token_observed"] is True
    assert mass["credential_evidence"]["jwt_claims"]["role"] == "admin"
    assert mass["credential_evidence"]["principal"]["email"].endswith("@example.test")
    assert mass["credential_evidence"]["principal"]["username"].startswith("user_")
    assert mass["credential_evidence"]["principal"]["password"].startswith("Test1234!")
    assert mass["credential_evidence"]["baseline_principal"]["email"].endswith("@example.test")
    assert mass["credential_evidence"]["baseline_principal"]["email"] != mass["credential_evidence"]["principal"]["email"]
    assert mass["credential_evidence"]["baseline_login_endpoint"] == "/rest/user/login"
    assert mass["credential_evidence"]["privileged_access_proof"]["endpoint"] == "/admin/panel"
    assert mass["credential_evidence"]["privileged_access_proof"]["noauth_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["baseline_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["elevated_status"] == 200
    assert "/api/users" in mass["credential_evidence"]["replay_commands"]["register"]
    assert "/api/users" in mass["credential_evidence"]["replay_commands"]["baseline_register"]
    assert "/rest/user/login" in mass["credential_evidence"]["replay_commands"]["relogin"]
    assert "/rest/user/login" in mass["credential_evidence"]["replay_commands"]["baseline_relogin"]
    assert "/admin/panel" in mass["credential_evidence"]["replay_commands"]["privileged_probe"]
    assert any(call["path"] == "https://app.example.test/rest/user/login" for call in session.calls)


@pytest.mark.asyncio
async def test_api_security_uses_openapi_write_probe_for_privileged_differential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _OpenApiPrivilegedMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    proof = mass["credential_evidence"]["privileged_access_proof"]
    assert proof["endpoint"] == "/api/admin/users/1/role"
    assert proof["method"] == "POST"
    assert proof["baseline_status"] == 403
    assert proof["elevated_status"] == 200
    assert "-X POST" in mass["credential_evidence"]["replay_commands"]["privileged_probe"]
    assert "/api/admin/users/1/role" in mass["credential_evidence"]["replay_commands"]["privileged_probe"]


class _JwtOnlyMassAssignmentSession(_MassAssignmentSession):
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        parsed = urlparse(path)
        route = parsed.path or path
        body = dict(kwargs.get("json_data") or {})
        self.calls.append({"method": method, "path": path, "kwargs": kwargs})

        if method == "POST" and route == "/api/users":
            account = {
                "email": str(body.get("email") or ""),
                "password": str(body.get("password") or ""),
                "username": str(body.get("username") or ""),
                "role": str(body.get("role") or "user"),
            }
            self.accounts.append(account)
            return _Resp(
                201,
                json.dumps({"status": "success", "data": {"email": account["email"], "role": account["role"]}}),
                {"content-type": "application/json"},
            )

        if method == "POST" and route == "/rest/user/login":
            identity = str(body.get("email") or body.get("username") or "")
            password = str(body.get("password") or "")
            account = next(
                (
                    item
                    for item in self.accounts
                    if identity in {item.get("email", ""), item.get("username", "")}
                    and password == item.get("password", "")
                ),
                None,
            )
            if account:
                return _Resp(
                    200,
                    json.dumps(
                        {
                            "authentication": {
                                "token": _jwt(
                                    {
                                        "data": {
                                            "email": account.get("email", ""),
                                            "id": 7,
                                            "role": account.get("role", ""),
                                            "username": account.get("username", ""),
                                        }
                                    }
                                )
                            }
                        }
                    ),
                    {"content-type": "application/json"},
                )
            return _Resp(401, json.dumps({"status": "error"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_extracts_effective_role_from_nested_jwt_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _JwtOnlyMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    assert mass["credential_evidence"]["jwt_claims"]["data"]["role"] == "admin"
    assert mass["credential_evidence"]["effective_role"] == "admin"


class _AssetDerivedMassAssignmentSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.accounts: list[dict[str, str]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        body = dict(kwargs.get("json_data") or {})
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")

        if method == "GET" and route == "/":
            return _Resp(200, '<html><script src="/static/js/main.js"></script></html>')

        if method == "GET" and route == "/static/js/main.js":
            return _Resp(
                200,
                'const svc="identity/";const routes={LOGIN:"api/auth/login",SIGNUP:"api/auth/signup"};',
            )

        if method == "POST" and route == "/identity/api/auth/signup":
            account = {
                "email": str(body.get("email") or ""),
                "password": str(body.get("password") or ""),
                "username": str(body.get("username") or ""),
                "role": str(body.get("role") or "user"),
            }
            self.accounts.append(account)
            return _Resp(
                201,
                json.dumps({"status": "success", "user": {"email": account["email"], "role": account["role"]}}),
                {"content-type": "application/json"},
            )

        if method == "POST" and route == "/identity/api/auth/login":
            identity = str(body.get("email") or body.get("username") or "")
            password = str(body.get("password") or "")
            account = next(
                (
                    item
                    for item in self.accounts
                    if identity in {item.get("email", ""), item.get("username", "")}
                    and password == item.get("password", "")
                ),
                None,
            )
            if account:
                return _Resp(
                    200,
                    json.dumps(
                        {
                            "authentication": {
                                "token": _jwt(
                                    {
                                        "email": account["email"],
                                        "id": 9,
                                        "role": account["role"],
                                        "username": account["username"],
                                    }
                                )
                            }
                        }
                    ),
                    {"content-type": "application/json"},
                )
            return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})

        if method == "GET" and route == "/admin/panel":
            if not auth:
                return _Resp(403, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if any(
                auth == f"Bearer { _jwt({'email': item['email'], 'id': 9, 'role': item['role'], 'username': item['username']}) }"
                and item.get("role") == "admin"
                for item in self.accounts
            ):
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_uses_asset_derived_signup_and_login_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _AssetDerivedMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    assert mass["endpoint"] == "/identity/api/auth/signup"
    assert mass["credential_evidence"]["login_endpoint"] == "/identity/api/auth/login"
    assert mass["credential_evidence"]["privileged_access_proof"]["endpoint"] == "/admin/panel"


class _DiscoveredPrivilegedEndpointSession(_MassAssignmentSession):
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        parsed = urlparse(path)
        route = parsed.path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")

        if route == "/api/admin/users/1/role":
            if not auth:
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if any(
                auth == f"Bearer {item.get('token', '')}" and item.get("role") == "admin"
                for item in self.accounts
            ):
                return _Resp(200, json.dumps({"ok": True, "role": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return await super().request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_api_security_uses_discovered_endpoints_for_privileged_differential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _DiscoveredPrivilegedEndpointSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
        discovered_endpoints=[{"path": "/api/admin/users/1/role"}],
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    proof = mass["credential_evidence"]["privileged_access_proof"]
    assert proof["endpoint"] == "/api/admin/users/1/role"
    assert proof["method"] == "POST"
    assert proof["baseline_status"] == 403
    assert proof["elevated_status"] == 200


class _MethodNotAllowedRateLimitSession:
    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        route = urlparse(path).path or path
        if method == "POST" and route in {"/api/login", "/api/auth/login", "/login"}:
            return _Resp(405, json.dumps({"error": "method_not_allowed"}), {"content-type": "application/json"})
        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_ignores_405_only_rate_limit_noise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _MethodNotAllowedRateLimitSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute("https://app.example.test")

    assert [f for f in result["findings"] if f["type"] == "no_rate_limit"] == []


class _AuthenticatedSelfWriteMassAssignmentSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.admin_token = ""

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        body = dict(kwargs.get("json_data") or {})

        if method == "POST" and route == "/api/v2/user/change-email":
            if auth != "Bearer tok-foothold":
                return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})
            if not body.get("email"):
                return _Resp(400, json.dumps({"error": "email required"}), {"content-type": "application/json"})
            role = str(body.get("role") or "user")
            token = _jwt({"email": str(body["email"]), "role": role, "username": "alice"})
            if role == "admin":
                self.admin_token = token
            return _Resp(
                200,
                json.dumps(
                    {
                        "authentication": {"token": token},
                        "user": {"email": str(body["email"]), "role": role},
                    }
                ),
                {"content-type": "application/json"},
            )

        if method == "GET" and route == "/admin/panel":
            if auth == f"Bearer {self.admin_token}":
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_uses_discovered_self_write_paths_for_mass_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _AuthenticatedSelfWriteMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
        identities=[
            {"name": "alice", "token": "tok-foothold"},
            {"name": "bob", "token": "tok-bob"},
        ],
        discovered_paths=["/api/v2/user/change-email"],
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    assert mass["endpoint"] == "/api/v2/user/change-email"
    assert mass["credential_evidence"]["mutation_method"] == "POST"
    assert mass["credential_evidence"]["persisted_role"] == "admin"
    assert mass["credential_evidence"]["privileged_access_proof"]["endpoint"] == "/admin/panel"
    assert mass["credential_evidence"]["privileged_access_proof"]["baseline_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["elevated_status"] == 200


class _AdaptiveSelfWriteMassAssignmentSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.admin_token = ""

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        body = dict(kwargs.get("json_data") or {})

        if method == "POST" and route == "/api/v2/user/change-email":
            if auth != "Bearer tok-foothold":
                return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})
            if not body.get("old_email") or not body.get("new_email"):
                return _Resp(
                    400,
                    json.dumps(
                        {
                            "message": "Validation failed",
                            "details": (
                                "Field error in object 'changeEmailForm' on field 'old_email': rejected value [null]; "
                                "Field error in object 'changeEmailForm' on field 'new_email': rejected value [null]"
                            ),
                        }
                    ),
                    {"content-type": "application/json"},
                )
            role = "admin" if str(body.get("role") or "") == "admin" else "user"
            token = _jwt({"email": str(body["new_email"]), "role": role, "username": "alice"})
            if role == "admin":
                self.admin_token = token
            return _Resp(
                200,
                json.dumps(
                    {
                        "authentication": {"token": token},
                        "message": "verification sent",
                    }
                ),
                {"content-type": "application/json"},
            )

        if method == "GET" and route == "/admin/panel":
            if auth == f"Bearer {self.admin_token}":
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_adapts_self_write_body_from_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _AdaptiveSelfWriteMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
        identities=[
            {"name": "alice", "token": "tok-foothold", "email": "alice@example.test"},
            {"name": "bob", "token": "tok-bob", "email": "bob@example.test"},
        ],
        discovered_endpoints=[
            {
                "path": "/api/v2/user/dashboard",
                "preview_auth": json.dumps(
                    {"email": "alice@example.test", "number": "5550101234", "name": "Alice"}
                ),
            }
        ],
        discovered_paths=["/api/v2/user/change-email"],
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    assert mass["endpoint"] == "/api/v2/user/change-email"
    assert mass["credential_evidence"]["persisted_role"] == "admin"
    assert mass["credential_evidence"]["privileged_access_proof"]["baseline_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["elevated_status"] == 200
    replay = mass["credential_evidence"]["replay_commands"]["self_write"]
    assert '"old_email":"alice@example.test"' in replay
    assert '"new_email":"' in replay
    successful = [
        call
        for call in session.calls
        if call["method"] == "POST"
        and call["path"] == "https://app.example.test/api/v2/user/change-email"
        and (call["kwargs"].get("json_data") or {}).get("old_email") == "alice@example.test"
    ]
    assert successful


class _ReloginSelfWriteMassAssignmentSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.password = "OrigPass!2026"
        self.role = "user"
        self.admin_token = ""

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        body = dict(kwargs.get("json_data") or {})

        if method == "POST" and route == "/api/v2/user/change-password":
            if auth != "Bearer tok-foothold":
                return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})
            if not body.get("new_password") or not body.get("repeat_password"):
                return _Resp(
                    400,
                    json.dumps(
                        {
                            "message": "Validation failed",
                            "details": (
                                "Field error in object 'changePasswordForm' on field 'new_password': rejected value [null]; "
                                "Field error in object 'changePasswordForm' on field 'repeat_password': rejected value [null]"
                            ),
                        }
                    ),
                    {"content-type": "application/json"},
                )
            if body.get("new_password") != body.get("repeat_password"):
                return _Resp(400, json.dumps({"error": "mismatch"}), {"content-type": "application/json"})
            self.password = str(body.get("new_password") or self.password)
            self.role = "admin" if str(body.get("role") or "") == "admin" else "user"
            return _Resp(200, json.dumps({"status": "updated"}), {"content-type": "application/json"})

        if method == "POST" and route == "/internal/auth/login":
            email = str(body.get("email") or "")
            password = str(body.get("password") or "")
            if email == "x":
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if email == "baseline-check@example.invalid":
                return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})
            if email == "alice@example.test" and password == self.password:
                token = _jwt({"email": email, "role": self.role, "username": "alice"})
                if self.role == "admin":
                    self.admin_token = token
                return _Resp(
                    200,
                    json.dumps(
                        {
                            "authentication": {"token": token},
                            "user": {"email": email, "role": self.role, "username": "alice"},
                        }
                    ),
                    {"content-type": "application/json"},
                )
            return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})

        if method == "GET" and route == "/admin/panel":
            if auth == f"Bearer {self.admin_token}":
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_relogs_after_self_write_password_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _ReloginSelfWriteMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
        login_paths=["/internal/auth/login"],
        identities=[
            {"name": "alice", "token": "tok-foothold", "email": "alice@example.test"},
            {"name": "bob", "token": "tok-bob", "email": "bob@example.test"},
        ],
        discovered_paths=["/api/v2/user/change-password"],
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    assert mass["endpoint"] == "/api/v2/user/change-password"
    assert mass["credential_evidence"]["login_endpoint"] == "/internal/auth/login"
    assert mass["credential_evidence"]["persisted_role"] == "admin"
    assert mass["credential_evidence"]["principal"]["email"] == "alice@example.test"
    assert mass["credential_evidence"]["principal"]["password"].startswith("Test1234!")
    assert mass["credential_evidence"]["privileged_access_proof"]["baseline_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["elevated_status"] == 200
    assert "/internal/auth/login" in mass["credential_evidence"]["replay_commands"]["relogin"]
    assert any(call["path"] == "https://app.example.test/internal/auth/login" for call in session.calls)


class _CredentialSeedSelfWriteMassAssignmentSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.password = "OrigPass!2026"
        self.role = "user"
        self.admin_token = ""

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        body = dict(kwargs.get("json_data") or {})

        if method == "POST" and route == "/api/v2/user/change-password":
            if auth != "Bearer tok-foothold":
                return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})
            if not body.get("currentPassword") or not body.get("newPassword") or not body.get("repeatPassword"):
                return _Resp(
                    400,
                    json.dumps(
                        {
                            "message": "Validation failed",
                            "details": (
                                "Field error in object 'changePasswordForm' on field 'currentPassword': rejected value [null]; "
                                "Field error in object 'changePasswordForm' on field 'newPassword': rejected value [null]; "
                                "Field error in object 'changePasswordForm' on field 'repeatPassword': rejected value [null]"
                            ),
                        }
                    ),
                    {"content-type": "application/json"},
                )
            if body.get("currentPassword") != self.password:
                return _Resp(403, json.dumps({"error": "bad_current_password"}), {"content-type": "application/json"})
            if body.get("newPassword") != body.get("repeatPassword"):
                return _Resp(400, json.dumps({"error": "mismatch"}), {"content-type": "application/json"})
            self.password = str(body.get("newPassword") or self.password)
            self.role = "admin" if str(body.get("role") or "") == "admin" else "user"
            return _Resp(200, json.dumps({"status": "updated"}), {"content-type": "application/json"})

        if method == "POST" and route == "/internal/auth/login":
            email = str(body.get("email") or "")
            password = str(body.get("password") or "")
            if email == "x":
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if email == "baseline-check@example.invalid":
                return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})
            if email == "alice@example.test" and password == self.password:
                token = _jwt({"email": email, "role": self.role, "username": "alice"})
                if self.role == "admin":
                    self.admin_token = token
                return _Resp(
                    200,
                    json.dumps(
                        {
                            "authentication": {"token": token},
                            "user": {"email": email, "role": self.role, "username": "alice"},
                        }
                    ),
                    {"content-type": "application/json"},
                )
            return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})

        if method == "GET" and route == "/admin/panel":
            if auth == f"Bearer {self.admin_token}":
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_uses_credentials_to_fill_current_password_and_relogin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _CredentialSeedSelfWriteMassAssignmentSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
        login_paths=["/internal/auth/login"],
        credentials=[{"email": "alice@example.test", "password": "OrigPass!2026"}],
        identities=[
            {"name": "alice", "token": "tok-foothold"},
            {"name": "bob", "token": "tok-bob"},
        ],
        discovered_paths=["/api/v2/user/change-password"],
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    replay = mass["credential_evidence"]["replay_commands"]["self_write"]
    assert mass["endpoint"] == "/api/v2/user/change-password"
    assert mass["credential_evidence"]["login_endpoint"] == "/internal/auth/login"
    assert mass["credential_evidence"]["principal"]["email"] == "alice@example.test"
    assert mass["credential_evidence"]["persisted_role"] == "admin"
    assert '"currentPassword":"OrigPass!2026"' in replay
    assert '"newPassword":"' in replay
    assert '"repeatPassword":"' in replay
    assert mass["credential_evidence"]["privileged_access_proof"]["baseline_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["elevated_status"] == 200


class _CredentialSeedProfileChangeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.email = "alice@example.test"
        self.username = "alice"
        self.password = "OrigPass!2026"
        self.role = "user"
        self.admin_token = ""

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        from urllib.parse import urlparse

        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        route = urlparse(path).path or path
        auth = str((kwargs.get("headers") or {}).get("Authorization") or "")
        body = dict(kwargs.get("json_data") or {})

        if method == "POST" and route == "/api/v2/user/change-profile":
            if auth != "Bearer tok-foothold":
                return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})
            required = (
                "currentEmail",
                "newEmail",
                "currentUsername",
                "newUsername",
                "passwordConfirmation",
            )
            if any(not body.get(key) for key in required):
                return _Resp(
                    400,
                    json.dumps(
                        {
                            "message": "Validation failed",
                            "details": (
                                "Field error in object 'changeProfileForm' on field 'currentEmail': rejected value [null]; "
                                "Field error in object 'changeProfileForm' on field 'newEmail': rejected value [null]; "
                                "Field error in object 'changeProfileForm' on field 'currentUsername': rejected value [null]; "
                                "Field error in object 'changeProfileForm' on field 'newUsername': rejected value [null]; "
                                "Field error in object 'changeProfileForm' on field 'passwordConfirmation': rejected value [null]"
                            ),
                        }
                    ),
                    {"content-type": "application/json"},
                )
            if body.get("currentEmail") != self.email or body.get("currentUsername") != self.username:
                return _Resp(403, json.dumps({"error": "bad_current_identity"}), {"content-type": "application/json"})
            if body.get("passwordConfirmation") != self.password:
                return _Resp(403, json.dumps({"error": "bad_confirmation"}), {"content-type": "application/json"})
            self.email = str(body.get("newEmail") or self.email)
            self.username = str(body.get("newUsername") or self.username)
            self.role = "admin" if str(body.get("role") or "") == "admin" else "user"
            return _Resp(200, json.dumps({"status": "updated"}), {"content-type": "application/json"})

        if method == "POST" and route == "/internal/auth/login":
            email = str(body.get("email") or "")
            username = str(body.get("username") or "")
            password = str(body.get("password") or "")
            if email == "x":
                return _Resp(401, json.dumps({"error": "missing"}), {"content-type": "application/json"})
            if email == "baseline-check@example.invalid":
                return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})
            if username == self.username and password == self.password:
                token = _jwt({"email": self.email, "role": self.role, "username": self.username})
                if self.role == "admin":
                    self.admin_token = token
                return _Resp(
                    200,
                    json.dumps(
                        {
                            "authentication": {"token": token},
                            "user": {"email": self.email, "role": self.role, "username": self.username},
                        }
                    ),
                    {"content-type": "application/json"},
                )
            return _Resp(401, json.dumps({"error": "invalid"}), {"content-type": "application/json"})

        if method == "GET" and route == "/admin/panel":
            if auth == f"Bearer {self.admin_token}":
                return _Resp(200, json.dumps({"ok": True, "scope": "admin"}), {"content-type": "application/json"})
            return _Resp(403, json.dumps({"error": "forbidden"}), {"content-type": "application/json"})

        return _Resp(404, "not found")


@pytest.mark.asyncio
async def test_api_security_handles_current_and_new_identity_aliases_for_self_write_relogin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _CredentialSeedProfileChangeSession()
    manager = _FakeSessionManager(session)
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)

    result = await test_api_security_mod.execute(
        "https://app.example.test",
        token="tok-foothold",
        login_paths=["/internal/auth/login"],
        credentials=[
            {
                "email": "alice@example.test",
                "username": "alice",
                "password": "OrigPass!2026",
            }
        ],
        identities=[
            {"name": "alice", "token": "tok-foothold"},
            {"name": "bob", "token": "tok-bob"},
        ],
        discovered_paths=["/api/v2/user/change-profile"],
    )

    mass = next(f for f in result["findings"] if f["type"] == "mass_assignment")
    replay = mass["credential_evidence"]["replay_commands"]["self_write"]
    relogin = mass["credential_evidence"]["replay_commands"]["relogin"]
    assert mass["endpoint"] == "/api/v2/user/change-profile"
    assert mass["credential_evidence"]["login_endpoint"] == "/internal/auth/login"
    assert mass["credential_evidence"]["identity"] == "username"
    assert mass["credential_evidence"]["principal"]["email"] != "alice@example.test"
    assert mass["credential_evidence"]["principal"]["username"] != "alice"
    assert '"currentEmail":"alice@example.test"' in replay
    assert '"currentUsername":"alice"' in replay
    assert '"newEmail":"' in replay
    assert '"newUsername":"' in replay
    assert '"passwordConfirmation":"OrigPass!2026"' in replay
    assert '"username":"' in relogin
    assert mass["credential_evidence"]["privileged_access_proof"]["baseline_status"] == 403
    assert mass["credential_evidence"]["privileged_access_proof"]["elevated_status"] == 200
