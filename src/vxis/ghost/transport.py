"""GhostTransport — httpx AsyncBaseTransport 래퍼.

요청마다 GhostLayer에서 proxy/UA를 받아 적용.
"""
from __future__ import annotations

import logging

import httpx

from vxis.ghost.layer import GhostLayer

logger = logging.getLogger(__name__)

try:
    import curl_cffi.requests as _curl  # noqa: F401
    _CURL_AVAILABLE = True
    logger.debug("[Ghost] curl_cffi 감지 — 향후 TLS fingerprint transport에 사용 가능")
except ImportError:
    _CURL_AVAILABLE = False
    logger.debug("[Ghost] curl_cffi 미설치 — httpx transport만 사용")

# 브라우저 헤더 세트 (Chrome 120 기준)
_BROWSER_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def _make_transport(proxy: str | None) -> httpx.AsyncBaseTransport:
    """프록시 URL로 httpx transport 생성."""
    if proxy:
        return httpx.AsyncHTTPTransport(proxy=proxy)
    return httpx.AsyncHTTPTransport()


class GhostTransport(httpx.AsyncBaseTransport):
    """요청마다 Ghost 설정을 적용하는 httpx transport 래퍼."""

    def __init__(
        self,
        layer: GhostLayer,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._layer = layer
        self._inner = inner  # 테스트 주입용
        self._transports: dict[str, httpx.AsyncBaseTransport] = {}

    def _transport_for_proxy(self, proxy: str | None) -> httpx.AsyncBaseTransport:
        key = proxy or "__direct__"
        transport = self._transports.get(key)
        if transport is None:
            transport = _make_transport(proxy)
            self._transports[key] = transport
        return transport

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        proxy = self._layer.next_proxy()
        transport = self._inner or self._transport_for_proxy(proxy)

        # UA 교체
        ua = self._layer.next_ua()
        headers = dict(request.headers)
        headers["user-agent"] = ua

        # 브라우저 헤더 주입 (이미 있는 헤더는 덮어쓰지 않음)
        lower_keys = {h.lower() for h in headers}
        for k, v in _BROWSER_HEADERS.items():
            if k.lower() not in lower_keys:
                headers[k] = v

        new_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=headers,
            content=request.content,
        )

        logger.debug(
            "[Ghost] %s %s  proxy=%s  ua=%.40s...",
            new_request.method, new_request.url, proxy or "direct", ua,
        )

        return await transport.handle_async_request(new_request)

    async def aclose(self) -> None:
        if self._inner:
            await self._inner.aclose()
        for transport in self._transports.values():
            await transport.aclose()
        self._transports.clear()
