from __future__ import annotations

import asyncio

import pytest

from vxis.agent.tools.proxy_runtime import ProxyRuntime
from vxis.interaction.xray import CapturedFlow


class _FakeMitm:
    def __init__(self, flows: list[CapturedFlow]) -> None:
        self._flows = flows
        self.proxy_url = "http://localhost:8081"
        self.is_running = True
        self._capture_dir = "/tmp/vxis-xray-test"

    def get_captured_flows(self):
        return list(self._flows)


def _sample_flows() -> list[CapturedFlow]:
    return [
        CapturedFlow(
            id="mitm-0000",
            timestamp=1.0,
            method="POST",
            url="https://example.test/login",
            request_headers={"content-type": "application/x-www-form-urlencoded"},
            request_body="username=admin&password=test",
            status_code=302,
            response_headers={"location": "/admin"},
            response_body="",
        ),
        CapturedFlow(
            id="mitm-0001",
            timestamp=2.0,
            method="GET",
            url="https://example.test/admin/users?id=1",
            request_headers={"cookie": "session=abc"},
            request_body="",
            status_code=200,
            response_headers={"content-type": "application/json"},
            response_body='{"id":1,"role":"admin"}',
        ),
    ]


def test_proxy_runtime_lists_views_and_builds_sitemap():
    runtime = ProxyRuntime()
    runtime.backend = "xray"
    runtime._xray = _FakeMitm(_sample_flows())

    requests = asyncio.run(runtime.list_requests(filter_expr="method:POST"))
    assert requests["count"] == 1
    assert requests["requests"][0]["path"] == "/login"

    view = asyncio.run(runtime.view_request("mitm-0001", part="response"))
    assert view["status_code"] == 200
    assert "admin" in view["body"]

    sitemap = asyncio.run(runtime.list_sitemap())
    assert sitemap["count"] == 2
    assert any(entry["path"] == "/admin/users" for entry in sitemap["entries"])


def test_proxy_runtime_scope_filters_requests():
    runtime = ProxyRuntime()
    runtime.backend = "xray"
    runtime._xray = _FakeMitm(_sample_flows())

    asyncio.run(runtime.scope_rules(action="set", allowlist=["*/admin/*"]))
    requests = asyncio.run(runtime.list_requests())

    assert requests["count"] == 1
    assert requests["requests"][0]["path"] == "/admin/users"
