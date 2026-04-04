"""GhostLayer — 익명화 레이어 싱글턴."""
from __future__ import annotations

import logging
import random
import re
from dataclasses import dataclass

from vxis.ghost.ua_pool import UA_POOL

logger = logging.getLogger(__name__)

_PROXY_URL_RE = re.compile(r"^(https?|socks5?)://[^/]+:\d+$")


@dataclass
class GhostTiming:
    mean: float = 3.0
    sigma: float = 2.0
    min_delay: float = 0.5
    max_delay: float = 15.0


class GhostLayer:
    """프로세스 레벨 싱글턴. 활성화되면 모든 TargetSession이 익명화 모드로 동작."""

    _instance: GhostLayer | None = None

    def __new__(cls) -> GhostLayer:
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._active = False
            inst._proxy_pool: list[str] = []
            inst._proxy_index = 0
            inst._timing = GhostTiming()
            cls._instance = inst
        return cls._instance

    def activate(self, proxy_pool: list[str] | None = None) -> None:
        valid: list[str] = []
        for p in (proxy_pool or []):
            if _PROXY_URL_RE.match(p):
                valid.append(p)
            else:
                logger.warning("[Ghost] 잘못된 프록시 URL 무시: %s", p)
        self._proxy_pool = valid
        self._proxy_index = 0
        self._active = True
        logger.info(
            "[Ghost] 익명화 활성화 — 프록시: %d개, UA풀: %d종",
            len(self._proxy_pool), len(UA_POOL),
        )

    def deactivate(self) -> None:
        self._active = False
        self._proxy_pool = []
        self._proxy_index = 0
        logger.info("[Ghost] 익명화 비활성화")

    def is_active(self) -> bool:
        return self._active

    def next_proxy(self) -> str | None:
        if not self._proxy_pool:
            return None
        proxy = self._proxy_pool[self._proxy_index % len(self._proxy_pool)]
        self._proxy_index += 1
        return proxy

    def next_ua(self) -> str:
        return random.choice(UA_POOL)

    def next_delay(self) -> float:
        t = self._timing
        raw = random.gauss(t.mean, t.sigma)
        return max(t.min_delay, min(t.max_delay, raw))


# 모듈 레벨 싱글턴 인스턴스
ghost_layer = GhostLayer()
