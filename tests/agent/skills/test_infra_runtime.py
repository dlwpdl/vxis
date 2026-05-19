from __future__ import annotations

import asyncio


class _FakeResponse:
    def __init__(self) -> None:
        self.status = 404
        self.body_length = 0
        self.text = ""


class _FakeSession:
    async def request(self, method, path, **kwargs):
        return _FakeResponse()


def test_test_infra_uses_short_timeouts_for_cloud_and_firebase(monkeypatch) -> None:
    import importlib

    test_infra = importlib.import_module("vxis.agent.skills.test_infra")

    session_requests: list[tuple[str, dict]] = []

    class _FakeManager:
        def __init__(self) -> None:
            self._session = _FakeSession()

        async def get_session(self, base_url: str, **kwargs):
            session_requests.append((base_url, dict(kwargs)))
            return self._session

        async def close_all(self) -> None:
            return None

    monkeypatch.setattr("vxis.interaction.hands.SessionManager", _FakeManager)

    asyncio.run(
        test_infra.execute(
            "https://example.com",
            allow_direct_cloud_metadata_probe=True,
        )
    )

    cloud_calls = [
        kwargs
        for base_url, kwargs in session_requests
        if "169.254.169.254" in base_url or "metadata.google.internal" in base_url
    ]
    assert cloud_calls, "expected metadata probes to allocate dedicated sessions"
    assert all(kwargs.get("timeout") == 4.0 for kwargs in cloud_calls)

    firebase_calls = [
        kwargs
        for base_url, kwargs in session_requests
        if "firebaseio.com" in base_url
    ]
    assert firebase_calls, "expected firebase probe to allocate a dedicated session"
    assert all(kwargs.get("timeout") == 5.0 for kwargs in firebase_calls)
