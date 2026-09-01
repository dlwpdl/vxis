from __future__ import annotations

import importlib
from typing import Any

import pytest

post_auth_enum_mod = importlib.import_module("vxis.agent.skills.post_auth_enum")


class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self.text = text

    @property
    def body_length(self) -> int:
        return len(self.text.encode())


class _FakeSession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity or "anonymous"

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if self.identity == "anonymous":
            return _Resp(401, "login required")
        if path == "/api/Orders/":
            if self.identity == "alice":
                return _Resp(200, '[{"id":1001,"owner":"alice","total":25}]')
            if self.identity == "bob":
                return _Resp(200, '[{"id":1002,"owner":"bob","total":40}]')
        return _Resp(404, "not found")


class _FakeSessionManager:
    def __init__(self) -> None:
        self.identities: list[str | None] = []

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        self.identities.append(identity)
        return _FakeSession(identity)


@pytest.mark.asyncio
async def test_post_auth_enum_enriches_identities_with_owned_object_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _FakeSessionManager()
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: manager)
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", ["/api/Orders/"])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[
            {"name": "alice", "token": "tok-alice"},
            {"name": "bob", "token": "tok-bob"},
        ],
    )

    assert result["owner_map"]["1001"] == "alice"
    assert result["owner_map"]["1002"] == "bob"
    assert result["object_patterns"][0]["url_pattern"].endswith("/api/Orders/{id}")
    assert set(result["object_patterns"][0]["object_ids"]) == {"1001", "1002"}
    bob = next(item for item in result["identities"] if item["name"] == "bob")
    assert "1002" in bob["owned_ids"]
    assert "alice" in manager.identities
    assert "bob" in manager.identities


def test_stateful_seed_plans_keeps_later_valid_candidates() -> None:
    plans = post_auth_enum_mod._stateful_seed_plans(
        {
            "/api/shop/orders/all",
            "/api/v2/community/posts/recent",
            "/chatbot/api/shop/orders/all",
            "/chatbot/api/v2/community/posts/recent",
            "/community/api/shop/orders/all",
            "/community/api/v2/community/posts/recent",
            "/identity/api/shop/orders/all",
            "/identity/api/v2/community/posts/recent",
            "/workshop/api/shop/orders/all",
            "/workshop/api/v2/community/posts/recent",
        }
    )

    assert {"read_path": "/workshop/api/shop/orders/all", "write_path": "/workshop/api/shop/orders"} in plans


class _ExclusiveVisibilitySession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity or "anonymous"

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if self.identity == "anonymous":
            return _Resp(401, "login required")
        if path == "/api/Orders/":
            if self.identity == "alice":
                return _Resp(200, '[{"id":1001},{"id":1002}]')
            if self.identity == "bob":
                return _Resp(200, '[{"id":1002},{"id":1003}]')
        return _Resp(404, "not found")


class _ExclusiveVisibilityManager:
    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _ExclusiveVisibilitySession(identity)


@pytest.mark.asyncio
async def test_post_auth_enum_uses_cross_identity_exclusive_ids_as_owner_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _ExclusiveVisibilityManager(),
    )
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", ["/api/Orders/"])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[
            {"name": "alice", "token": "tok-alice"},
            {"name": "bob", "token": "tok-bob"},
        ],
    )

    assert result["owner_map"] == {"1001": "alice", "1003": "bob"}
    alice = next(item for item in result["identities"] if item["name"] == "alice")
    bob = next(item for item in result["identities"] if item["name"] == "bob")
    assert alice["owned_ids"] == ["1001"]
    assert bob["owned_ids"] == ["1003"]
    assert result["object_patterns"][0]["owner_map"] == {"1001": "alice", "1003": "bob"}
    assert set(result["object_patterns"][0]["object_ids"]) == {"1001", "1002", "1003"}


class _StateSeedStorage:
    def __init__(self) -> None:
        self.posts: dict[str, list[str]] = {"alice": [], "bob": []}


class _StateSeedSession:
    def __init__(self, storage: _StateSeedStorage, identity: str | None) -> None:
        self.storage = storage
        self.identity = identity or "anonymous"

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        if self.identity == "anonymous":
            if path == "/api/posts/recent":
                return _Resp(401, "login required")
            return _Resp(404, "not found")
        if method == "GET" and path == "/api/posts/recent":
            posts = [{"id": item, "title": item, "content": "seeded"} for item in self.storage.posts[self.identity]]
            return _Resp(200, '{"posts":' + __import__("json").dumps(posts) + "}")
        if method == "POST" and path == "/api/posts":
            body = dict(kwargs.get("json_data") or {})
            if not body.get("title") or not body.get("content"):
                return _Resp(400, "missing fields")
            created = f"{self.identity}-post-{len(self.storage.posts[self.identity]) + 1}"
            self.storage.posts[self.identity].append(created)
            return _Resp(201, f'{{"id":"{created}"}}')
        return _Resp(404, "not found")


class _StateSeedManager:
    def __init__(self) -> None:
        self.storage = _StateSeedStorage()

    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _StateSeedSession(self.storage, identity)


@pytest.mark.asyncio
async def test_post_auth_enum_seeds_stateful_objects_from_collection_suffix_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _StateSeedManager(),
    )
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", ["/api/posts/recent", "/api/posts"])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[
            {"name": "alice", "token": "tok-alice"},
            {"name": "bob", "token": "tok-bob"},
        ],
    )

    assert result["owner_map"] == {"alice-post-1": "alice", "bob-post-1": "bob"}
    assert result["object_patterns"][0]["url_pattern"].endswith("/api/posts/{id}")
    assert set(result["object_patterns"][0]["object_ids"]) == {"alice-post-1", "bob-post-1"}
    assert result["object_patterns"][0]["owner_map"] == {
        "alice-post-1": "alice",
        "bob-post-1": "bob",
    }
    assert result["control_evidence"]["stateful_seeding"][0]["write_path"] == "/api/posts"


class _SpaBaselineSession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity or "anonymous"

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        shell = "<!doctype html><html><div id='root'></div></html>"
        if self.identity == "anonymous":
            if path == "/definitely-not-real-xyz-probe":
                return _Resp(200, shell)
            if path == "/rest/user/whoami":
                return _Resp(401, "login required")
            if path == "/api/Users/1":
                return _Resp(200, shell)
            return _Resp(404, "not found")
        if path == "/api/Users/1":
            return _Resp(200, shell)
        if path == "/rest/user/whoami":
            return _Resp(200, '{"id":"7","email":"alice@example.test","role":"user"}')
        return _Resp(404, "not found")


class _SpaBaselineManager:
    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _SpaBaselineSession(identity)


@pytest.mark.asyncio
async def test_post_auth_enum_filters_spa_shell_false_positives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vxis.interaction.hands.SessionManager", lambda: _SpaBaselineManager())
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", ["/api/Users/1", "/rest/user/whoami"])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[{"name": "alice", "token": "tok-alice", "role": "user"}],
    )

    assert [item["path"] for item in result["accessible"]] == ["/rest/user/whoami"]
    assert [item["path"] for item in result["new_endpoints"]] == ["/rest/user/whoami"]
    assert all(item["path"] != "/api/Users/1" for item in result["accessible"])


class _AssetDerivedPostAuthSession:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity or "anonymous"

    async def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        shell = "<!doctype html><html><script src='/static/js/main.js'></script><div id='root'></div></html>"
        if self.identity == "anonymous":
            if path == "/definitely-not-real-xyz-probe":
                return _Resp(200, shell)
            if path == "/":
                return _Resp(200, shell)
            if path == "/static/js/main.js":
                return _Resp(
                    200,
                    'const a="community/";const b="identity/";const routes={RECENT:"api/v2/community/posts/recent",DASH:"api/v2/user/dashboard",CHANGE:"api/v2/user/change-email"};',
                )
            if path == "/community/api/v2/community/posts/recent":
                return _Resp(401, '{"error":"Unauthorized"}')
            if path == "/identity/api/v2/user/dashboard":
                return _Resp(404, '{"message":"Given Email is not registered!"}')
            return _Resp(404, "not found")
        if path == "/":
            return _Resp(200, shell)
        if path == "/static/js/main.js":
            return _Resp(
                200,
                'const a="community/";const b="identity/";const routes={RECENT:"api/v2/community/posts/recent",DASH:"api/v2/user/dashboard",CHANGE:"api/v2/user/change-email"};',
            )
        if path == "/community/api/v2/community/posts/recent":
            return _Resp(200, '{"posts":[{"id":"p1","email":"robot001@example.com"}]}')
        if path == "/identity/api/v2/user/dashboard":
            return _Resp(200, '{"id":"7","email":"alice@example.test","role":"user"}')
        return _Resp(404, "not found")


class _AssetDerivedPostAuthManager:
    async def get_session(self, base_url: str, *, identity: str | None = None, **kwargs: Any):
        return _AssetDerivedPostAuthSession(identity)


@pytest.mark.asyncio
async def test_post_auth_enum_discovers_prefixed_routes_from_js_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _AssetDerivedPostAuthManager(),
    )
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", [])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[{"name": "alice", "token": "tok-alice", "role": "user"}],
    )

    paths = [item["path"] for item in result["accessible"]]
    assert "/community/api/v2/community/posts/recent" in paths
    assert "/identity/api/v2/user/dashboard" in paths
    assert any(item["path"] == "/community/api/v2/community/posts/recent" for item in result["new_endpoints"])
    assert "/identity/api/v2/user/change-email" in result["discovered_paths"]


@pytest.mark.asyncio
async def test_post_auth_enum_prefers_collection_base_for_object_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vxis.interaction.hands.SessionManager",
        lambda: _AssetDerivedPostAuthManager(),
    )
    monkeypatch.setattr(post_auth_enum_mod, "AUTH_PATHS", [])

    result = await post_auth_enum_mod.execute(
        "https://app.example.test",
        token="tok-alice",
        identities=[{"name": "alice", "token": "tok-alice", "role": "user"}],
    )

    patterns = result["object_patterns"]
    assert len(patterns) == 1
    assert patterns[0]["url_pattern"].endswith("/community/api/v2/community/posts/{id}")
    assert set(patterns[0]["object_ids"]) == {"p1"}
    assert patterns[0]["owner_map"] == {}
    assert result["owner_map"] == {}
    assert result["identities"][0]["owned_ids"] == []
    assert all("/recent/{id}" not in item["url_pattern"] for item in patterns)
    assert all("/dashboard/{id}" not in item["url_pattern"] for item in patterns)
